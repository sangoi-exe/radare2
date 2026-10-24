# MS-DOS 6.22 and Windows 3.11 lab

## Owner and proof boundary

The durable lab root is `/home/lucas/work/radare2/.refs/labs/dos622-win311/`. All paths below are relative to that root unless stated otherwise. No required lab execution input remains in the retired task-cache root. Keep the proprietary media and installed guests outside Git.

This lab boots genuine installed Microsoft MS-DOS 6.22 and Windows 3.11 through two observed routes: the preserved DOSBox-X baseline and separate non-root QEMU 8.2.2/KVM evaluation disks. DOSBox-X CPU effects remain emulator observations. The KVM route has completed the unchanged observer control, seven NE relocation variants, four LEAVE encodings and one ARPL case, as detailed below. QEMU still supplies virtual firmware and devices, and virtualization can require hypervisor handling. Enabled KVM does not mean every machine operation bypasses emulation. It does not establish physical386 timing or peripheral equivalence. Neither route qualifies all 16-bit software or all native suites.

Execute the relevant target case before accepting a claim about 16-bit machine or DOS/Windows behavior, then compare the observation with our real production consumers. Self-derived simulations do not establish external behavior. Keep host/native tests for our consumers and host-only contracts; not all native suites run as Win16. Record a missing target run as a proof gap. Keep file segment ordinal, observed runtime selector, actual relocated bytes and C48 analysis coordinate separate. Synthetic selector substitution is not Windows byte equality.

## Retained inputs and observations

| Path or dependency | Use |
| --- | --- |
| Workspace `.refs/Microsoft MS-DOS 6.22 Plus Enhanced Tools (3.5).7z` | Original DOS installation media; retained intact. |
| Workspace `.refs/Microsoft Windows 3.11 (Retail Full) (3.5).7z` | Original Windows installation media; retained intact. |
| `runtime/dos622-win311/disk-c.img` | Installed sparse MBR/FAT16 disk; partition offset 32256 bytes. Logical size 268369920 bytes, with 47584 allocated 512-byte blocks at relocation. |
| `runtime/qemu-kvm/disk-c.img`, `runtime/qemu-kvm/disk-run2.img` | Retained first and second KVM control evaluation copies. |
| `runtime/qemu-kvm/ne-batch-1/disk-c.img`, `runtime/qemu-kvm/instructions-1/disk-c.img` | Evaluated eight-input NE batch and LEAVE/ARPL disks. Preserve these and every earlier evaluated disk; future runs use a new writable sparse copy of the baseline. |
| `runtime/dos622-win311/control/boot.conf` | Reusable hard-disk boot: `IMGMOUNT C /lab/disk-c.img -ide 1m`, then `BOOT C:`. |
| `runtime/dos622-win311/control/create.conf` | Historical one-use IMGMAKE operation. Never run against the installed disk. |
| `runtime/dos622-win311/control/dos-setup.conf` | Historical DOS installation route, not the normal boot route. |
| `build/dos622-win311/dos-media/` | Extracted DOS floppy images, including the retained supplemental disk. |
| `build/dos622-win311/windows-media/`, `build/dos622-win311/windows-install/` | Extracted Windows media and installation files. |
| `sources/win16-observer/` | Observer source, DEF and link response; preserve their existing line endings. |
| `build/win16-observer/probe.exe`, `build/ne-variants/` | Frozen observer and relocation witnesses, not disposable merely because they are under `build/`. |
| `sources/win16-instructions/`, `build/win16-instructions/instr.exe` | C/separate USE16 FAR assembly sources, README format/build documentation and the 6982-byte executed instruction observer. |
| `runtime/guest-c/` | Earlier host-directory Windows environment, retained history; not the genuine DOS hard-disk boot. |
| `evidence/dos622-win311/` | Genuine-DOS installation, boot and control observations. Earlier comparison evidence remains elsewhere under `evidence/`. |
| `evidence/qemu-kvm/preparation/`, `evidence/qemu-kvm/run-2/` | Native copied-disk/startup preparation and the fully observed KVM control. |
| `evidence/qemu-kvm/ne-batch-1/preparation/`, `evidence/qemu-kvm/ne-batch-1/run-1/` | Frozen-input readbacks/startup preparation and all eight raw NE outputs, comparison, collection record, invocation/monitor and captures. |
| `evidence/win16-instructions/preparation/`, `evidence/qemu-kvm/instructions-1/preparation/`, `evidence/qemu-kvm/instructions-1/run-1/` | Instruction build evidence, copied-disk preparation and the 132-byte `INSTR.BIN`, `observations.txt`, `collection.json`, invocation/monitor and two captures. |

The existing Docker images are separate daemon-owned dependencies, not files missing from the relocated tree:

- DOSBox-X and native image tools: `sha256:2b0acefc166770181c98903cc776dc935fbd927b1d97b760b28a603752021bec`.
- Borland observer compiler/linker: `sha256:c7885c69809e1afbe6be1ebd744f32b089b7abe4a6f850b47ff0d453141457ba`.

Both images have no declared Docker volumes. The observer build recipe is retained in `evidence/preparation/commands.txt`, with compiler/linker output beside it. Its historical host paths and container names are records, not current commands. Rebuilding the observer is separate from booting the frozen witness. External host/bridge comparison SDKs are not guest boot inputs.

Within `evidence/dos622-win311/`, `boot-1/invocation.txt` owns the successful historical boot invocation, `boot-1/dosbox-terminal.raw` retains the terminal and quit confirmation, and `control-run-1/collection.log` retains native collection commands. These files intentionally keep their original cache paths. Do not rewrite them or create a compatibility link. The 17 old stopped lab containers retain stale bind roots; do not restart them. Launch a new named container with the current roots instead.

The genuine-DOS control result is the 10-byte `evidence/dos622-win311/control-run-1/CTRL.BIN`: `56 00 d7 14 a5 5a 56 00 d7 14`. The first six bytes are the relocated slot and tail; the last four independently report the target pointer. This run observed target `14d7:0056`, not the earlier lab's `1577:0056`. Runtime selectors are observations, not fixed expectations for later boots. Only the control has run on this disk; the seven relocation variants have not been repeated here. See the [qualification record](../.sangoi/task-logs/2026-10-24-native-pro-followup.md#genuine-dos-lab-qualification-and-independent-selector-observation) for coverage limits.

The relocated DOSBox-X baseline boot was observed through fresh binds, reported DOS 6.22 and exited normally; its evidence is `evidence/dos622-win311/relocated-boot-1/`. The fully observed KVM control is in `evidence/qemu-kvm/run-2/`: `invocation.txt` retains the actual launch, `monitor.raw` records `kvm support: enabled` and exit code 0, `001-windows311-kvm.jpg` shows Windows 3.11/386 Enhanced Mode, and `002-dos622-kvm.jpg` shows DOS 6.22 after normal Windows exit. `collection.txt` and `KVMCTRL.BIN` retain the stopped-image result `56 00 5f 15 a5 5a 56 00 5f 15`, with matching independent target `155f:0056` and intact A5/5A tail. Keep these records and both control evaluation disks frozen. The first KVM launch produced a retained result but lacked observed GUI/monitor control, so it is not the fully observed qualification route.

## Observed KVM cases

The eight-input NE batch executed CTRL (collected as `VCTRL.BIN`), O32N, P48N, P32A, O32A, P48A, P32M and O32M on its separate disk. All eight 10-byte results independently report target `155f:0056`. The tested `0x0d` cases changed only the offset WORD, the `0x0b` cases had far16:16 effects, and additive pointer cases summed the two WORDs independently; every A5/5A tail remained intact. These effects match the earlier Windows measurements, not raw-selector byte equality across environments. See `evidence/qemu-kvm/ne-batch-1/run-1/comparison.txt` and the [hardware-backed NE batch record](../.sangoi/task-logs/2026-10-24-native-pro-followup.md#hardware-backed-ne-batch) for exact bytes and limits.

The separate instruction run returned 132 bytes with status 5, four completed LEAVE cases and one completed ARPL case. LAR succeeded with SS rights `0x0000f300` and D/B clear; actual CS was `1567`, DS=SS `155f`. Each LEAVE case began ESP=`8001177c`, EBP=`da5b178c`, with SS:BP payload `a1b2c3d4`. `C9` and `67 C9` produced ESP=`8001178e`, EBP=`da5bc3d4`; `66 C9` and `66 67 C9` produced ESP=`80011790`, EBP=`a1b2c3d4`. Upper ESP remained intact independently of operand-selected pop width. ARPL destination `1566` with source `1567` became `1567`, ZF=1. No constructed selector was loaded into a segment register; this is not execution of the complete CS-copy/DS-load F7 sequence. The [hardware-backed instruction record](../.sangoi/task-logs/2026-10-24-native-pro-followup.md#hardware-backed-instruction-observations), raw `INSTR.BIN`, `observations.txt` and source README own the measured fields and proof limits.

Both runs recorded enabled KVM, Windows 3.11/386 Enhanced Mode, normal Windows exit and QEMU exit 0; outputs were collected only after shutdown, without an observed guest error dialog. These target observations remain the external foundation. Production translation initially matched only C9 (1/4); correcting the three prefixed Protected16 stack assignments matched all four captured LEAVE register results (4/4). The bridge pins that corrected engine and passed local matching plugin/language qualification; the [task log's F4 consumer-comparison record](../.sangoi/task-logs/2026-10-24-native-pro-followup.md) owns the detailed proof. Native tests are consumer comparisons, not replacement target observations. NE and full selector-value/F7 corrections remain pending; no whole-suite or physical386 qualification follows from these cases.

## Fresh QEMU/KVM control run

Host preparation is complete: QEMU x86 system/GUI packages are version `1:8.2.2+ds-0ubuntu1.18`, and `lucas` belongs to the existing `kvm` group. Non-root uid1000 obtained KVM API 12 with `/dev/kvm` still root:kvm mode0660. Existing shells do not automatically acquire a newly added supplementary group; the demonstrated `sg kvm` route supplies that context without restarting WSL. Do not repeat privileged setup or run QEMU as root. Docker images remain separate daemon-owned tools; this host's Docker data owner is `/var/lib/docker`, not `.cache`.

Before launch, supply the exact path of a separately prepared fresh writable sparse disk copy under `runtime/qemu-kvm/`. Native sparse copying and stopped-image mtools are sufficient; no maintained preparer is needed. Retain copy equality before the intended startup change, read back the changed startup, verify the unchanged observer and confirm the chosen output is absent before execution. The demonstrated preparation preserves the original 89-byte AUTOEXEC.BAT prefix and appends one 54-byte DOS CRLF line, `C:\WINDOWS\WIN.COM C:\PROBE\PROBE.EXE C:\KVMCTRL.BIN`, for a total of 143 bytes. Its evidence is in `evidence/qemu-kvm/preparation/run2/`. A new run must not write the baseline, any evaluated disk listed above or existing output evidence.

Acquire current Computer Use `DISPLAY` and host `XAUTHORITY` values as described below for DOSBox-X; do not copy their historical values or authentication contents. Run the following directly in a connected interactive Bash terminal/PTY, with `disk` already set to the fresh prepared-copy path. Do not launch it through an exhausted heredoc or another closed stdin: a code block alone does not provide the interactive HMP monitor. The native `script` command records that connected terminal; it does not replace it. Fresh evidence names must not collide.

```bash
set -eu
lab=/home/lucas/work/radare2/.refs/labs/dos622-win311
: "${disk:?Set disk to the exact fresh prepared writable copy}"
: "${DISPLAY:?Set DISPLAY from the fresh Computer Use session}"
: "${XAUTHORITY:?Set XAUTHORITY from the fresh Computer Use session}"
test -f "$disk"
test -w "$disk"
test -f "$XAUTHORITY"
test ! "$disk" -ef "$lab/runtime/dos622-win311/disk-c.img"
test ! "$disk" -ef "$lab/runtime/qemu-kvm/disk-c.img"
test ! "$disk" -ef "$lab/runtime/qemu-kvm/disk-run2.img"
run_id=$(date -u +%Y%m%dT%H%M%SZ)
capture="$lab/evidence/qemu-kvm/run-$run_id"
mkdir "$capture"
qemu=(env "DISPLAY=$DISPLAY" "XAUTHORITY=$XAUTHORITY" GDK_BACKEND=x11 "TMPDIR=$lab/runtime/qemu-kvm/tmp" /usr/bin/qemu-system-x86_64 -name "radare2-win311-kvm-$run_id" -machine pc -accel kvm -cpu host -smp 1 -m 16M -drive "file=$disk,format=raw,if=ide,index=0" -vga std -display gtk,gl=off -nic none -serial none -parallel none -monitor stdio -no-reboot -pidfile "$capture/qemu.pid")
printf -v qemu_command '%q ' "${qemu[@]}"
printf -v launch_command '%q ' sg kvm -c "$qemu_command"
/usr/bin/script --quiet --return --flush "$capture/monitor.raw" --command "$launch_command"
```

These are the observed run-2 machine/accelerator/CPU/memory/display options with fresh paths and names. `GDK_BACKEND=x11` selects the current X11 session instead of an inherited Wayland display. `-accel kvm` requires KVM; failure is not permission to fall back to TCG. Guest networking is absent. Keep the invocation, VM identity and screenshots under the fresh capture owner without retaining credentials.

At the connected `(qemu)` monitor, enter `info kvm` and require `kvm support: enabled`. A supported accelerator listed by `-accel help`, a live window or a process exit status alone does not prove enabled KVM or guest success. Through native Computer Use, observe Windows About Program Manager's version and 386 Enhanced Mode, and the observer's actual return or error. Exit Windows normally to DOS; run `ver` and retain the observed version. Only after Windows has exited and disk activity has settled, enter `quit` in the monitor. Wait for QEMU and the terminal recorder to exit normally before collection. A missing monitor, failed control, unexpected exit or ambiguous disk writer stops the operation for inspection.

For a prepared copy whose fresh guest result is `C:\KVMCTRL.BIN`, the following stopped-image collection uses a new native-tool container and read-only disk bind. Change the result name to match the actual prepared run if needed; do not reuse an old guest result as proof of fresh execution.

```sh
image=sha256:2b0acefc166770181c98903cc776dc935fbd927b1d97b760b28a603752021bec
docker run --name "r2-kvm-collect-$run_id" --network none --read-only --user 1000:1000 --mount "type=bind,src=$disk,dst=/disk.img,readonly" --mount "type=bind,src=$capture,dst=/capture" --entrypoint /usr/bin/mcopy "$image" -n -i /disk.img@@32256 ::/KVMCTRL.BIN /capture/KVMCTRL.BIN
od -An -tx1 "$capture/KVMCTRL.BIN"
```

Native `/usr/bin/mtype -i /disk.img@@32256 ::/KVMCTRL.BIN` can also read the chosen result from the same stopped read-only image. Retain native statuses and raw bytes, then compare them with the real production consumer. Runtime selector values can change; do not replace them with static segment ordinals or extend this control result to unrun variants/instructions. The preserved DOSBox-X route below remains available as a distinct baseline, not a silent fallback for a failed KVM run.

## Fresh DOSBox-X boot

Use this route only for an authorized lab operation. Before launch, verify that no guest, image tool or other process writes this disk. Inspect running containers and their mounts, native guest/image-tool processes and open image handles. Do not stage or collect while the guest is active. Do not reinstall DOS/Windows or run IMGMAKE on this existing image.

Obtain a fresh Computer Use session and use that session's live `DISPLAY` and host `XAUTHORITY` file. Set both shell variables from the current runtime, not from a historical invocation or an unrelated shell session. Never retain authentication contents or passwords in evidence. This procedure uses the abstract X11 transport demonstrated by the historical invocation; host networking supports that transport, not guest networking. Guest IPX and NE2000 remain disabled in `boot.conf`.

Run the following from a Bash shell after acquiring those current GUI values. `capture` must be new; a name collision stops the operation. The historical invocation used uid/gid 1000, the current lab owner's identity. Check ownership before using this route under another account.

```sh
set -eu
lab=/home/lucas/work/radare2/.refs/labs/dos622-win311
image=sha256:2b0acefc166770181c98903cc776dc935fbd927b1d97b760b28a603752021bec
: "${DISPLAY:?Set DISPLAY from the fresh Computer Use session}"
: "${XAUTHORITY:?Set XAUTHORITY from the fresh Computer Use session}"
test -f "$XAUTHORITY"
run_id=$(date -u +%Y%m%dT%H%M%SZ)
container="r2-dos622-win311-$run_id"
capture="$lab/evidence/dos622-win311/run-$run_id"
mkdir "$capture"
docker run -d -it --name "$container" --network host --read-only --user 1000:1000 -e "DISPLAY=$DISPLAY" -e XAUTHORITY=/pilot.xauth -e HOME=/home/pilot -e TMPDIR=/home/pilot/tmp -e SDL_AUDIODRIVER=dummy -e TERM=xterm-256color --mount "type=bind,src=$lab/runtime/dos622-win311,dst=/lab" --mount "type=bind,src=$lab/runtime/dos622-win311/control,dst=/control,readonly" --mount "type=bind,src=$lab/build/dos622-win311/dos-media,dst=/dos,readonly" --mount "type=bind,src=$capture,dst=/capture" --mount "type=bind,src=$lab/runtime/dos622-win311/gui-home,dst=/home/pilot" --mount "type=bind,src=$XAUTHORITY,dst=/pilot.xauth,readonly" --workdir /capture --entrypoint /usr/bin/script "$image" --quiet --return --flush /capture/dosbox-terminal.raw --command '/usr/local/bin/dosbox-x -nopromptfolder -defaultdir /capture -fastlaunch -conf /control/boot.conf'
```

The container root is read-only; only the explicit lab, GUI-home and capture binds are writable. Retain the new container identity, invocation and screenshots under the fresh capture owner, without copying GUI credentials. A successful container start is not proof of guest boot.

Through native Computer Use, observe the DOS prompt and run `ver`; start Windows with `win` and check About Program Manager. The established baseline reported MS-DOS 6.22 and Windows 3.11 in 386 Enhanced Mode. Use observed key events if text insertion fails; do not execute a partially inserted command.

For a separately authorized unchanged control, run `c:\probe\probe.exe c:\NEWCTRL.BIN` from Windows Program Manager, with a fresh output filename. The observer requires an unquoted DOS filename. Preserve the old `C:\CTRL.BIN`; a new output name distinguishes fresh execution from stale results. Wait for return or an error dialog and record what actually happened. Do not treat a failed control as relocation evidence.

## Safe exit and stopped-image file access

Exit Windows normally to DOS and wait for disk activity to finish. Then request DOSBox-X Quit through its native GUI. The retained run displayed a guest-system quit warning in the existing console because GUI dialog helpers were absent. If that happens, attach only to the exact new owned container and answer the observed confirmation after confirming the guest is safely back in DOS:

```sh
docker attach --sig-proxy=false "$container"
```

The observed prompt was `Are you sure to quit anyway now?` followed by `y/n:`; the operator answered `y` and Enter. Do not assume that closing a window completed exit. Wait for completion and inspect status before touching the disk:

```sh
docker wait "$container"
docker inspect --format '{{.Name}} {{.State.Status}} exit={{.State.ExitCode}}' "$container"
```

Normal historical exit was `exited`, code 0. A running container, unexpected exit or ambiguous disk state stops collection pending inspection; do not replace normal shutdown with an unexamined force stop.

Only while all image users are stopped, use native mtools at the established partition offset. A fresh helper container must also use the relocated roots. This collection example uses the same shell variables, read-only image access and the fresh run's evidence destination:

```sh
docker run --name "$container-collect" --network none --read-only --user 1000:1000 --mount "type=bind,src=$lab/runtime/dos622-win311,dst=/lab,readonly" --mount "type=bind,src=$capture,dst=/capture" --entrypoint /usr/bin/mcopy "$image" -n -i /lab/disk-c.img@@32256 ::/NEWCTRL.BIN /capture/NEWCTRL.BIN
od -An -tx1 "$capture/NEWCTRL.BIN"
```

Use the actual fresh guest output name if it differs. Inspect the native command status, retain raw output and compare observations with the relevant real host/bridge/engine consumer. Do not normalize away runtime-selector differences or claim an unrun case passed.

For authorized staging, use a separate fresh image-tool container while the guest is stopped, a read-only input bind and a writable `/lab` bind. The demonstrated native form is `/usr/bin/mcopy -n -i /lab/disk-c.img@@32256 /input/NEWFILE.EXE ::/PROBE/NEWFILE.EXE`; use a new destination name and check the status. The demonstrated listing form is `/usr/bin/mdir -i /lab/disk-c.img@@32256 ::/PROBE/`. Do not overwrite frozen witnesses or access the image concurrently. Native staging and collection do not require a shared-folder driver, reinstall, permanent launcher or new controller.
