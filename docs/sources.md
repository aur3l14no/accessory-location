# Sources and acknowledgements

This implementation was informed by public protocol research and interoperability
analysis. The references below document protocol behavior; third-party binaries,
identity files, and captured device sessions are not included in the repository.

- [JJTech0130's CarKit probe](https://gist.github.com/JJTech0130/a878496479afedb93dd02399551e3aec):
  USB lockdown service and control-session negotiation.
- [wiomoc's MFi/iAP research](https://wiomoc.de/misc/posts/mfi_iap.html) and
  [iap2 implementation](https://github.com/wiomoc/iap2): packet framing,
  identification, authentication, and Bluetooth transport.
- [xcertplay](https://github.com/shilapi/xcertplay): control-message identifiers,
  nested capability declarations, location subscriptions, and reporting intervals.
- [Showcase](https://github.com/amineross/showcase): BAA certificate message layout.
- [PlayPort](https://github.com/youcci/playport) and
  [DiPlay](https://github.com/shihabal3amri/DiPlay): local MFi-v3 authentication,
  challenge/signature encoding, and identity-provisioning background. These
  projects publish their source under GPL-3.0; consult their own notices for
  third-party material.
- [Accessory-location research](https://nvme0n1p.dev/posts/ios-location-modify)
  and [CarPlay authentication research](https://nvme0n1p.dev/posts/about-carplay-mfi):
  background on accessory-provided location and authentication boundaries.
- [Apple's location-source documentation](https://developer.apple.com/documentation/corelocation/cllocationsourceinformation/isproducedbyaccessory):
  the distinction between accessory-produced and other location sources.

The Python USB transport uses [pymobiledevice3](https://github.com/doronz88/pymobiledevice3).
Cryptographic operations use [cryptography](https://cryptography.io/).
