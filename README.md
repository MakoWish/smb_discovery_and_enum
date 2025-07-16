# SMB Discovery and Enumeration

## About

This Python script leverages `masscan` and `Impacket` to scan a network segment, IP, or host for listening SMB services. For any devices found with SMB enabled, shares are enumerated, and access levels are tested.

This was written to assist with discovering excessive share permissions on the domain to prevent unnecessary information disclosure. 

Supports Kerberos since most Windows networks now require Kerberos for SMB access.

## Prerequisites

`masscan`

`impacket`
