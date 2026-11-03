# n94 13G37 execution evidence

These addresses refer only to the unmodified iPhone4,1 9.3.6 13G37 kernel
SHA256 `26418340b40613777a60cf2c12ddae2d148d9fe19c22bab475e450bdb4bf4c28`.
Diagnostic success is not an iOS boot success.

## Timebase

Run [41597110060](https://github.com/nustai/un1box-n94/actions/runs/41597110060)
passes corecrypto FIPS POST with the AIC timebase implementation.
At `0x800c8be0`, mach_absolute_time reads the global pointer at `0x803ff084`,
then HI/LO/HI at offsets `0x28/0x20/0x28`. QMP recorded pointer `0xc035a000`;
`gva2gpa` resolved it to physical `0x3f200000`. The earlier PMGR inference was
wrong and has been removed. Frequency 24 MHz remains a diagnostic assumption.

## NVRAM proxy

The stock DT `/chosen/nvram-proxy-data` contains 8192 zero bytes.
The 13G37 parser starts at `0x80368498`, reads a little-endian 16-bit block
count at current offset +2, multiplies it by 16, and adds it to the current
offset at `0x80368600`. Zero therefore prevents forward progress.
The diagnostic preparer supplies an empty volatile CHRP image, with `common`
and `free` partitions, each 4096 bytes. These capacities are emulator choices,
not claims about physical n94 flash layout.

The generic format and checksum were checked against Apple's
[XNU 3248 IONVRAM.cpp](https://github.com/apple-oss-distributions/xnu/blob/xnu-3248.60.10/iokit/Kernel/IONVRAM.cpp).
No hardware model or board constants were taken from a different device.
Run [41600925326](https://github.com/nustai/un1box-n94/actions/runs/41600925326)
passes the former loop and reaches AppleS5L8940XIO, AppleARMBacklight and
AppleKeyStore startup, then panics in AppleInterruptController::start.

## AIC INFO

The observed panic reports `ipid-mask property length is 24 but should be 0`.
In the stock n94 DT, AIC ipid-mask has six 32-bit words and #main-cpus is 2.
At `0x80f09716..0x80f09734`, the driver reads INFO at +4 twice. It extracts
bits 16..20 and adds one for CPU count, and retains bits 0..9 for IRQ count.
At `0x80f0973e..0x80f09754` it requires ceil(IRQ count /32)*4 mask bytes.
The model now advertises two CPUs and a capacity of 192 IRQs. This matches
the six-word mask; the precise physical count within 161..192 is still unknown.
INFO correction does not validate the remaining legacy AIC register model,
timer compares, interrupt acknowledgement, or secondary-core release.
