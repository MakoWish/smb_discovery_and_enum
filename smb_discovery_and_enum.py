#!/usr/bin/env python3
import os
import io
import csv
import sys
import json
import uuid
import socket
import argparse
import ipaddress
import subprocess
from pathlib import Path
from Logger import logger
from datetime import datetime
from functools import partial
from typing import List, Tuple
from impacket.smbconnection import SMBConnection
from concurrent.futures import ThreadPoolExecutor, as_completed


SKIP_SHARES = {"IPC$", "PRINT$", "ADMIN$", "NETLOGON", "SYSVOL"}
SKIP_SERVERS = {"SERVER1"}
MASSCAN_RATE = 10000  # packets-per-second to keep scans quick


# --------------------------------------------------------------------------- #
# Strip off the "FILE:" from KRB5CCNAME path
# --------------------------------------------------------------------------- #
cc = os.environ.get('KRB5CCNAME')
if cc and cc.lower().startswith('file:'):
	os.environ['KRB5CCNAME'] = cc.split(':', 1)[1]


# --------------------------------------------------------------------------- #
# Parse command line arguments
# --------------------------------------------------------------------------- #
def parse_args():
	parser = argparse.ArgumentParser(
		description="Scan a CIDR, list SMB shares, test permissions, export CSV"
	)
	parser.add_argument(
		"target",
		help="target(s) to scan, e.g. Server1, 10.10.10.10, 10.10.10.0/23"
	)
	parser.add_argument(
		"-d", "--domain", default="",
		help="AD domain (FQDN or NETBIOS)"
	)
	parser.add_argument(
		"-u", "--username", default="",
		help="Username"
	)
	parser.add_argument(
		"-p", "--password", default="",
		help="Password (omit with -k)"
	)
	parser.add_argument(
		"-k", "--kerberos", action="store_true",
		help="Use Kerberos / ticket cache"
	)
	parser.add_argument(
		"--hashes", default=None,
		help="LM:NT or :NT hashes instead of password"
	)
	parser.add_argument(
		"--dc-ip", dest="dc_ip", default=None,
		help="Domain Controller IP (override)"
	)
	parser.add_argument(
		"-o", "--output", default="smb_results.csv",
		help="Output CSV filename"
	)
	parser.add_argument(
		"--rate", type=int, default=MASSCAN_RATE,
		help="masscan packet rate"
	)
	parser.add_argument(
		"-T", "--threads", type=int, default=10,
		help="Concurrent threads (default: 10)"
	)
	return parser.parse_args()


# --------------------------------------------------------------------------- #
# Check if provided target is an single IP address
# --------------------------------------------------------------------------- #
def is_ipv4_address(cidr):
		try:
			ip = ipaddress.IPv4Address(cidr)
			return True
		except ipaddress.AddressValueError:
			return False


# --------------------------------------------------------------------------- #
# Check if provided target is a valid CIDR range
# --------------------------------------------------------------------------- #
def is_ipv4_cidr(cidr):
		try:
			ipaddress.IPv4Network(cidr, strict=False)
			return True
		except ValueError:
			return False

# --------------------------------------------------------------------------- #
# Scan CIDR with masscan, return list of IPs with 445/tcp open
# --------------------------------------------------------------------------- #
def run_masscan(cidr: str, rate: int = MASSCAN_RATE) -> List[str]:
	cmd = [
		"masscan", "-p445", cidr,
		"--rate", str(rate),
		"--wait", "2",
		"-oJ", "-"               # JSON to STDOUT
	]
	try:
		result = subprocess.run(
			cmd, capture_output=True, text=True, check=True
		)
	except subprocess.CalledProcessError as exc:
		logger.error(f"masscan exited with {exc.returncode} – {exc.stderr}", file=sys.stderr)
		sys.exit(1)

	live_ips = []
	for line in result.stdout.splitlines():
		# Each line is a JSON object {"ip":"x.x.x.x", "ports":[...]}
		try:
			obj = json.loads(line)
			live_ips.append(obj["ip"])
		except Exception:
			continue
	return live_ips


# --------------------------------------------------------------------------- #
# Resolve hostname – Kerberos needs a proper SPN (\\HOSTNAME)
# --------------------------------------------------------------------------- #
def resolve_hostname(ip: str) -> str | None:
	try:
		hostname, _, _ = socket.gethostbyaddr(ip)
		return hostname.split(".")[0]
	except socket.herror:
		return None


# --------------------------------------------------------------------------- #
# Resolve hostname – Kerberos needs a proper SPN (\\HOSTNAME)
# --------------------------------------------------------------------------- #
def resolve_ip(hostname: str) -> str | None:
	try:
		ip = socket.gethostbyname(hostname)
		return ip
	except socket.gaierror as e:
		logger.error("Hostname could not be resolved to IP!")
		return None
	except socket.herror:
		return None


# --------------------------------------------------------------------------- #
# Test a single share and decide READ / WRITE / MODIFY / FULL_CONTROL
# --------------------------------------------------------------------------- #
def classify_share(conn: SMBConnection, share: str) -> str:
	access = "NO ACCESS"

	# Test READ – try to list the root of the share
	try:
		conn.listPath(share, "*")
		access = "READ"
	except Exception:
		pass

	# Test WRITE (+ DELETE) – create, then delete a tiny temp file
	temp_name = f"__audit_{uuid.uuid4().hex[:8]}.tmp"
	try:
		audit_text = f'Auditing SMB share permissions on "\\\\{conn.getRemoteName()}\\{share}" - Information Security Team'
		data = io.BytesIO(audit_text.encode("utf-8"))
		conn.putFile(share, temp_name, data.read)
		conn.deleteFile(share, temp_name)
		access = "MODIFY" if access == "READ" else "WRITE"
	except Exception:
		# Could be read-only or no write permission
		pass

	return access


# --------------------------------------------------------------------------- #
# Enumerate shares on a host and classify each one
# --------------------------------------------------------------------------- #
def audit_host(
	ip: str, domain: str, user: str, password: str,
	use_kerberos: bool, hashes: str | None, dc_ip: str | None
) -> List[Tuple[str, str, str]]:
	hostname = resolve_hostname(ip)
	if not hostname:
		logger.warning(f"{ip} → no PTR hostname; skipping")
		return []

	if any(hostname.lower() == server.lower() for server in SKIP_SERVERS):
		return []

	logger.info(f"Auditing {hostname} ({ip}) …")

	try:
		conn = SMBConnection(remoteName=hostname, remoteHost=ip,
							 sess_port=445, timeout=15)
		if use_kerberos:
			conn.kerberosLogin(user, password, domain,
							   lmhash="", nthash="", aesKey="",
							   kdcHost=dc_ip, useCache=True)
		else:
			lm, nt = ("", "")
			if hashes:
				try:
					lm, nt = hashes.split(":")
				except ValueError:
					nt = hashes
			conn.login(user, password, domain, lm, nt)
	except TimeoutError as e:
		logger.error(f"[{hostname}] SMB connection timeout")
	except Exception as e:
		logger.error(f"[{hostname}] SMB auth failed: {e}")
		return []

	rows = []
	try:
		for share in conn.listShares():
			name = share["shi1_netname"][:-1]
			if any(name.lower() == share.lower() for share in SKIP_SHARES):
				continue
			lvl = classify_share(conn, name)
			if lvl != "NO ACCESS":                     # Don't report shares with no access
				rows.append((hostname, name, lvl))
	finally:
		conn.logoff()
	return rows


# --------------------------------------------------------------------------- #
# Main routine
# --------------------------------------------------------------------------- #
def main() -> None:
	args = parse_args()

	# Check what sort of target was passed
	if is_ipv4_cidr(args.target):
		# Valid CIDR range for masscan
		pass
	elif is_ipv4_address(args.target):
		# Single IP address. Append 32-bit mask	for masscan
		args.target = f"{args.target}/32"
	else:
		# Target is invalid IP/CIDR, or is hostname
		ip = resolve_ip(args.target)
		if is_ipv4_address(ip):
			args.target = f"{ip}/32"
		else:
			sys.exit(1)

	logger.info(f"Scanning {args.target} for port 445/tcp …")
	live_ips = run_masscan(args.target, rate=args.rate)
	logger.info(f"{len(live_ips)} hosts with 445 open")

	out_path = Path(args.output).expanduser()
	fh = out_path.open("w", newline="")
	writer = csv.writer(fh)
	writer.writerow(["Host", "Share", "Access"])
	fh.flush()

	worker = partial(
		audit_host,
		domain=args.domain,
		user=args.username,
		password=args.password,
		use_kerberos=args.kerberos,
		hashes=args.hashes,
		dc_ip=args.dc_ip
	)

	# ---- Thread pool ----------------------------------------------------- #
	with ThreadPoolExecutor(max_workers=args.threads) as pool:
		futures = {pool.submit(worker, ip): ip for ip in live_ips}

		for fut in as_completed(futures):
			rows = fut.result()
			for row in rows:
				writer.writerow(row)
			fh.flush()

	fh.close()
	logger.info(f"Done. Results written to {out_path}")


# --------------------------------------------------------------------------- #
# Application Entry Point
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
	try:
		# Start script execution timer
		start_time = datetime.now()

		# Run the main routine
		main()
	except KeyboardInterrupt:
		logger.info("Exiting due to keyboard interrupt...")
	finally:
		# End timer
		end_time = datetime.now()

		# Calculate time delta
		elapsed_time = end_time - start_time

		# Format delta as H:M:S
		hours, remainder = divmod(elapsed_time.total_seconds(), 3600)
		minutes, seconds = divmod(remainder, 60)

		logger.info(f"Script runtime: {int(hours)}h {int(minutes)}m {int(seconds)}s")
