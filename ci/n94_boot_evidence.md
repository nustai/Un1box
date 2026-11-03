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
existing n94 nominal-performance1 value (81920 in DT units). The second
record word remains zero; its full meaning and calibrated voltages are
unverified. Actual calibrated DVFS is not implemented.
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

Run [41606693696](https://github.com/nustai/un1box-n94/actions/runs/41606693696)
passes both earlier panics, but both variants spend 120 seconds polling
device-clock offset 0x1130. The last PC is repeatedly 0x80d96c72 (MMIO read),
LR 0x80d96baf. The loop at 0x80d96bae XORs the value with itself shifted
right four and waits for its low nibble to become zero: target and actual
must agree. The generic backing store returned 0xf even after writing OFF=0.
The n94 driver computes register=0x1000+clock_id*4 at 0x80d96b58; DT
device-clocks-min/max are 56/128. The clock range now stores target
and mirrors it into actual immediately, preserving zero and other bits.
This models synchronous virtual transitions; dependencies and latency remain
TODO. ARM smoke explicitly writes target 3 (expects actual/target 0x33), then
OFF=0 (expects zero), preventing the original fallback behavior from passing.

Run [41608657724](https://github.com/nustai/un1box-n94/actions/runs/41608657724)
passes the wait on clock 76 but reaches the same wait on clock 55 (+0x10dc).
The initial assumption that DT min=56 bounded the hardware register IDs was
wrong. At 0x80d96678 the stock driver explicitly visits IDs 9..87, then
cleans up 87..10 at 0x80d966aa. The model now covers 128 clock words starting
at +0x1000; exact DT min/max semantics remain TODO. ARM smoke tests clock 55
and clock 76 separately, including nonzero transitions and OFF=0.

Host build [41609546419](https://github.com/nustai/un1box-n94/actions/runs/41609546419)
passes the expanded clock regression. Kernel run
[41611008843](https://github.com/nustai/un1box-n94/actions/runs/41611008843)
passes both clock waits and reaches a new data abort at PC 0x80d97a2e,
LR 0x80d972cf, reading MMIO offset +4. The caller maps PL310 region 0;
its print format resolves to AppleS5L8940XPL310::start.
Stock n94 /arm-io/pl310 reg = (0x0e000000,0x1000,0x0fd00000,0x2000),
thus root ranges 0x3e000000 and 0x3fd00000. Neither is currently modeled.
Next work is PL310/cache-interface behavior, not more performance-table edits.

## Initial PL310 model

The n94 driver reads Cache Type at 0x80d972c4, derives ways/sets at
0x80d972e2, then programs DT-supplied latency/feature words at 0x80d97498.
It writes invalidate-by-way +0x77c at 0x80d975f2 and polls for zero.
The dedicated n94 model preserves observed control/latency/feature registers;
maintenance completes immediately because the QEMU memory model is coherent.
The generic operation offsets are checked against
[ARM DDI 0246A](https://documentation-service.arm.com/static/5e8e1ac088295d1e18d35cda).
This implementation is authored for the n94 DT, not copied from another board.
Cache ID/type default to diagnostic zero with QOM overrides; neither is a
claim about measured n94 geometry. Actual cache geometry remains TODO.
The second CIF range has only explicitly diagnostic backing and LOG_UNIMP
on every access; its command/status semantics remain unimplemented.
ARM smoke checks control write/read/reset, invalidate completion and CIF
backing/reset before it emits its UART marker on both machine aliases.

Host build [41614884721](https://github.com/nustai/un1box-n94/actions/runs/41614884721)
passes those ARM tests. Kernel runs 41615947906 and
[41616848328](https://github.com/nustai/un1box-n94/actions/runs/41616848328)
pass the old PL310 load and reach AppleCDMA. The latter's driver-init.log
retains executed blocks 0x80d97498, 0x80d975e0, 0x80d975f8, 0x80d97606 and
0x80d9760a: feature setup, invalidate request, poll and successful return.
No CIF access is recorded before this panic; its behavior remains untested.

The next fault is a store at 0x80c8e87c (AppleCDMA+0x87c), MMIO +8.
Stock n94 /arm-io/cdma reg=(0x07000000,0x2d000),(0x07800000,0x9000),
thus root bases 0x37000000/0x37800000. DT cdma-version=3, max-channel=44,
interrupt list has 44 entries 0x33..0x5e. Driver 0x80c8e790 maps region 0
into the pointer later used by that store. A real DMA/channel/IRQ model is
not yet present; register backing alone would not establish working DMA.
