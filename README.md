# EDRSilencer BOF

This is a port of the EDRSilencer tool (https://github.com/netero1010/EDRSilencer) to BOF format. It is designed to block outbound traffic for various EDR processes using Windows Filtering Platform (WFP) APIs.

## Usage
```
Usage: edrsilencer <blockedr/block/unblockall/unblock> [<program path>|<filter id>]
- Add WFP filters to block the IPv4 and IPv6 outbound traffic of all detected EDR processes:
  edrsilencer blockedr

- Add WFP filters to block the IPv4 and IPv6 outbound traffic of a specific process (full path is required):
  edrsilencer block "C:\Windows\System32\curl.exe"

- Remove all WFP filters applied by this tool:
  edrsilencer unblockall

- Remove a specific WFP filter based on filter id:
  edrsilencer unblock <filter id>
```

## Compile

Compile BOF:
`make`

Compile standalone .exe:
`make exe`

## Credits

- https://github.com/netero1010/EDRSilencer
- https://www.mdsec.co.uk/2023/09/nighthawk-0-2-6-three-wise-monkeys/

## Copyright
Copyright 2024 Aon plc
