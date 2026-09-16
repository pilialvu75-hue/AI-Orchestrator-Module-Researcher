# platform.power_thermal controlled discovery proof

This proof closes **research/discovery depth only** for the staged
`platform.power_thermal` need. It does not assert security admission, contract
conformance, runtime validation, Raspberry Pi hardware validation, or
certification.

## Signal model

Power and thermal signals are intentionally kept separate. Battery level,
charging/source state, raw temperatures, voltage/power sensors, OS thermal
pressure, Web compute pressure, and Raspberry Pi throttling flags may inform one
policy, but they are not interchangeable measurements.

The discovery pairs are target-aware:

- Android/iOS: `battery_plus` + `flutter_thermal`.
- Windows: `battery_plus` + LibreHardwareMonitor.
- Linux: `battery_plus` + lm-sensors.
- macOS: `battery_plus` + Stats.
- Web: `battery_plus` + the Compute Pressure binding in `js_bindings`.
- Raspberry Pi: lm-sensors + the official `vcgencmd` component in
  `raspberrypi/utils`.

## Important limitations

The Web pressure candidate is discontinued and has limited platform/browser
reach; CPU pressure is not direct temperature. LibreHardwareMonitor is kept only
as pinned Windows research evidence because its live preflight is `BLOCKED`.
Stats, lm-sensors, raspberrypi/utils, js_bindings, and battery_plus remain
`REVIEW` for the exact reasons persisted in the live evidence file.
`flutter_thermal` is the only candidate in this Ring whose full pinned preflight
is currently `CLEAR`.

No upstream code was executed. No Module Library read/write was performed.
