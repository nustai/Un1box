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

Run [41602251048](https://github.com/nustai/un1box-n94/actions/runs/41602251048)
passes that former panic and prints AIC external capacity 0xc0, four IPIs.
The following panic is a data abort at PC 0x8109f666, a direct GPIO register
load. Its caller 0x8109efdc loops over the port count with a four-byte stride.
Stock n94 DT /arm-io/gpio gives reg=(0x0fa00000,0x1000), #gpio-ports=28,
#interrupt-groups=8, parent interrupt=0x77; arm-io translation adds 0x30000000.
The driver class name printed by Apple's own n94 kernel includes S5L8930;
our model uses only this n94 DT and these n94 kernel instructions.
Post-panic QMP gva2gpa returned Unmapped, so physical GPIO identification
comes from the DT mapping path, not a successful post-panic MMU query.
The added diagnostic port bank deliberately leaves input and IRQ semantics
unimplemented and logs accesses outside the observed port word range.

GPIO host build [41602972643](https://github.com/nustai/un1box-n94/actions/runs/41602972643)
passes CPU-executed port read/write and reset checks on both machine names.
Kernel run [41603982852](https://github.com/nustai/un1box-n94/actions/runs/41603982852)
passes the earlier GPIO load and reaches AppleS5L8940XPerformanceController.
Both boot_args versions then panic in IOReporter::handleSwapCleanup with
one channel and dimension zero. Symbol lookup identifies the reporting path
at 0x80553984 as AppleARMPlatform, called from AppleS5L8940X+0x1d4c.
This is a performance-reporting dimension, not framebuffer resolution.
The source of the zero state count is still under investigation; do not
substitute panel dimensions or patch out the panic based on its wording.

## Performance boot data and slot control

AppleARMPlatform 0x805536f2..0x80553730 reads eight-byte voltage-states
records and terminates on the first zero performance. Stock voltage-states1
is 24 zero bytes. The diagnostic image now supplies one state using the
existing n94 nominal-performance1 value (81920 in DT units). Voltage remains
unknown/zero; actual calibrated DVFS is not implemented.
Run [41605346742](https://github.com/nustai/un1box-n94/actions/runs/41605346742)
passes IOReporter setup and prints domain 1 voltage/performance state counts
of one, then panics with `out of PERF_STATE registers`.
At 0x80d96230..0x80d9628a the n94 driver reads PMGR offset 0x300 and retains
its low nibble. The allocation loop starts with 16 and decrements until that
lower bound, panicking at 0x80d9644e when reached. The old generic PMGR 0xf
default thus leaves one slot. A separate +0x300 backing register now resets
to diagnostic zero (no bootloader-reserved slots), preserving zero writes.
Full register fields and the physical hardware/bootloader reset snapshot
remain unknown; zero is an explicit virtual boot ownership choice.
