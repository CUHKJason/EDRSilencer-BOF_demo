# EDRSilencer BOF

This is a fork of the EDRSilencer BOF (https://github.com/AonCyberLabs/EDRSilencer-BOF), to show the demo code snippet of creating custom sublayer (Line 160-184) and add WFP filter with different condition (e.g., block remote IP / block appID) (Line 196-258).

## Usage
```
Usage: edrsilencer <blockedr/blockip/block/unblockall/unblock> [<program path>|<filter id>]
- Demo code snippet to create custom sublayer and add WFP filter to block remote IPv4 142[.]250[.]71[.]174:  
  EDRSilencer blockip

- Add WFP filters to block the IPv4 and IPv6 outbound traffic of all detected EDR processes:
  EDRSilencer blockedr

- Add WFP filters to block the IPv4 and IPv6 outbound traffic of a specific process (full path is required):
  EDRSilencer block "C:\Windows\System32\curl.exe"

- Remove all WFP filters applied by this tool:
  EDRSilencer unblockall

- Remove a specific WFP filter based on filter id:
  EDRSilencer unblock <filter id>
```

## Compile

Compile BOF:
`make`

Compile standalone .exe:
`make exe`

## Credits

- https://github.com/AonCyberLabs/EDRSilencer-BOF
- https://github.com/netero1010/EDRSilencer
- https://www.mdsec.co.uk/2023/09/nighthawk-0-2-6-three-wise-monkeys/

