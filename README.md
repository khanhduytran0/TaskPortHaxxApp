# TaskPortHaxxApp
Attempt to manipulate platform process task port with CoreTrust bug alone. This is a PoC for iOS 17.0 semi-jailbreak without kernel exploit.

It used to be that having a CoreTrust (therefore TrollStore) bypass does not equal to a jailbreak. However, it it now possible to achieve a semi-jailbreak on these (at least until all supported versions for now, 16.7RC and 17.0)
Read below for more info.

- Update (2025-12-05): NathanLR 2.0 utilizing this PoC is out. You can get it [here](https://ios.cfw.guide/installing-nathanlr/#installing-nathanlr)

There are many loopholes used in this PoC:
- Launch Constraint bypass (for iOS 16.0+)
- Spawn root process from `launchd` without being a platform binary
- Arbitrary code execution in platform process by controlling a platform process's thread state via an exception port
- Userspace PAC bypass made trivial using hardware breakpoint

## Bypassing Launch Constraint
Since iOS 16.0, Apple introduced Launch Constraint which prevents many platform binaries from being executed under certain conditions. You can read more info about it [here](https://theapplewiki.com/wiki/Dev:Launch_Constraints)

For this chain to work, a Launch Constraint bypass is required to spawn the target platform binary. Although there’s a recent bypass ([CVE-2025-43253](https://wts.dev/posts/bypassing-launch-constraints)), it didn’t seem to work on iOS at all.

For most platform binaries, one of the requirements are that they have to be spawned by parent PID 1, aka `launchd`. Is there any way to fool Launch Constraint? A few ideas came to my mind:
- [double-fork](https://github.com/holyswordman/async_awake-fun/blob/d6201959a4017479fdc623fa4badeccb7e319618/async_wake_ios/the_fun_part/bootstrap.c#L89-L150): never tried this before since stock `fork()` is broken since iOS 15.
- double-`posix_spawn()` (similar to double-fork above): didn’t work
- `execve()`: didn’t work
- `posix_spawn()` with `POSIX_SPAWN_SETEXEC`: worked! Obviously, this is the same thing that `xpcproxy` used to spawn daemons, so Launch Constraint has to somehow allow it.

It is unknown whether it was patched at some point, Apple could probably patch this by checking it it was called from xpcproxy.

With a Launch Constraint bypass, we can now spawn platforms binaries. But, wait, we can’t just use `posix_spawn` since it is still required to have parent PID 1. Of course, we can use the main app itself which is spawned by launchd to spawn platform binary, but it is cumbersome since it would take down the entire app UI and we can only spawn one platform binary.

Another problem is that you will need root to get `launchd` task port. You can’t just mix `posix_spawnattr_set_persona_uid_np` and `POSIX_SPAWN_SETEXEC` to elevate to root directly, Apple knew it already. So we need to find a way to trick launchd into spawning a root process that we can control..

## Spawning a binary from launchd with root
It is common knowledge that `launchd` would reject any `launchctl` requests, including those that allow you to submit a launch job, unless your binary is a platform binary with root privilege.

My first thought was to borrow an arm64, unsandboxed, platform binary with no Launch Constraint using the rest of the PoC chain to submit a launch job for us. However, I had many issues with this so I abandoned this method.

Next, I tried to look into how `runningboardd` submits launch job to spawn app processes. I extracted its exact payload and put it in an app installed via TrollStore. Surprisingly, it worked! The launch job routine that `runningboardd` used is **not** protected by a platform binary check. Here’s how its payload looks like:

<table>
<tr><td>
<a href="https://github.com/khanhduytran0/TaskPortHaxxApp/blob/713d60ab36d7e4fa5d53a0504d98e25846dce8f8/TaskPortHaxxApp/launch.m#L47-L61"><b>TaskPortHaxxApp/launch.m</b></a><br/>
lines 47 to 61 in <a href="https://github.com/khanhduytran0/TaskPortHaxxApp/blob/713d60a"><code>713d60a</code></a>
</td></tr>
<tr><td>

```objc
NSDictionary *root = @{
    @"monitor": @NO,
    @"handle": @(0),
    @"type": @(7),
    @"plist": plist // plist dict is a typical launchd plist similar to those in /System/Library/LaunchDaemons
};

// Convert to xpc_object_t
xpc_object_t xpcDict = _CFXPCCreateXPCObjectFromCFObject(root);
// For some reason _CFXPCCreateXPCObjectFromCFObject doesn't produce correct uint64, so we set them again here
xpc_dictionary_set_uint64(xpcDict, "handle", 0);
xpc_dictionary_set_uint64(xpcDict, "type", 7);

xpc_object_t result;
kern_return_t kr = _launch_job_routine(0x3e8, xpcDict, &result);
```

</td></tr>
</table>

During testing this, I realized that I can respawn my UIKit app to run as root, such that a root helper would no longer be needed, unfortunately respawning didn’t work correctly on 17.0.

## Executing arbitrary code in platform processes
Putting two first steps together, we can successfully spawn a platform binary as root. Now that we need to find a way to gain code execution in it.

I had the very same idea as [psychicpaper’s method by Siguza](https://blog.siguza.net/psychicpaper/#4-escaping-the-sandbox). It’s worth checking it out since it provided the entire foundation to make this possible, but TL;DR: you can set an exception port to a platform binary via `posix_spawn` API. It’s done as the follows:
- Spawn our binary from `launchd` with root, as described above.
- From our binary, we use `posix_spawn` to spawn a platform binary with our controlled exception port and a fake bootstrap port. A fake bootstrap port is required to purposefully crash the victim process for our exception handler to be fired, as described in the psychicpaper’s blog post.

Once the exception port fires, we will get the victim’s task port and its thread state. However, we can do nothing with the task port we got since we are not a platform process. Fortunately, at this point we have total control over process’s registers. We can set anything unless it is PAC protected, which I will describe *some ways* to bypass it below. 

I have made a [`ProcessContext`](https://github.com/khanhduytran0/TaskPortHaxxApp/blob/pacbypass/TaskPortHaxxApp/ProcessContext.m) class which is essentially a wrapper around a process's exception handler with convenient methods to read/write as well as calling arbitrary functions. Reading and writing memory call `__atomic_load_X` and `__atomic_store_X` instead of some random gadgets :D. Also, dyld shared cache ASLR slide is the same across all processes, so we can just take our process's pointer and perform arbitrary calls directly.

> [!NOTE]
> ~~This technique was patched in iOS 18.0, so in the event of another CoreTrust bypass drops, a new technique is required. As noted by @alfiecg24, this is likely due to `thid_should_crash` mitigation, and palera1n had to set `thid_should_crash=0` boot arg to bypass this.~~
>
> Update: DarkSword use the very same exception handler technique, and disproved this by using kernel r/w to [bypass fatal crash](https://github.com/wh1te4ever/darksword-kexploit-fun/blob/5add59d715c8ed0accf140e90212af48f6ef78de/darksword-kexploit-fun/kexploit/kutils.m#L143-L149). As a result, this technique is known to work up to iOS 26.0.1, and may be more as long as you have kernel r/w.

## Bypassing userspace PAC
On arm64, everything above is enough to do anything with the victim process, including reading/writing memory and doing arbitrary function calls. However, for arm64e, we need a way to sign a `br` gadget that would allow us to completely bypass userspace PAC, since we can always set PC to reuse that signed `br` gadget.
~~Moreover, a userspace PAC bypass is required even if you have a kernel r/w exploit on iOS 17.0 to overwrite launchd executable path, since SPTM now manages userland PAC.~~ Turns out [DarkSword disproved this](https://github.com/wh1te4ever/darksword-kexploit-fun/blob/5add59d715c8ed0accf140e90212af48f6ef78de/darksword-kexploit-fun/TaskRop/Thread.m#L110-L114), as you could still overwrite `jop_pid` and `rop_pid` with kernel r/w alone.

Here are some approaches:

### Use `posix_spawnattr_set_ptrauth_task_port_np`
This is the quickest approach. Used in `opainject`, this allows you to steal another process’s PAC `IA` signing key and use it to sign pointers on your own, or you can force a platform process to use your app’s PAC signing key.

Unfortunately, Apple nuked it in iOS 16.6:
- [xnu-8796.121.2](https://github.com/apple-oss-distributions/xnu/blob/xnu-8796.121.2/bsd/kern/kern_exec.c#L2603-L2619): last version with known functional `posix_spawnattr_set_ptrauth_task_port_np` (16.5.1?)
- [xnu-8796.141.3](https://github.com/apple-oss-distributions/xnu/blob/xnu-8796.141.3/bsd/kern/kern_exec.c#L2603): they nuked it completely: `/* No one uses this, this is no longer supported, just a no-op */`. So `opainject`’s ROP/PAC bypass method is dead at some point in 16.6 or 16.6.1
- [xnu-10063.101.15](https://github.com/apple-oss-distributions/xnu/blob/xnu-10063.101.15/bsd/kern/kern_exec.c#L2703-L2721): Apple realized they still need it, but they put it behind `#if (DEVELOPMENT || DEBUG)` :/

### Brute-forcing approach
Okay so initially I thought if we couldn’t bypass it, let brute force do the job. It of course works but has extremely poor reliability and may take a long time. Here’s why:

Before sending thread state to userland exception handler, the kernel would [sign PC, LR, etc](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/arm64/status.c#L760-L768) with its own discriminator. If we try to modify PC, we need to clear `__DARWIN_ARM_THREAD_STATE64_FLAGS_KERNEL_SIGNED_PC` flag otherwise the kernel would reject it.
When receiving a modified thread state from userland, the kernel would validate PC using a userland-specfic discriminator, a combination of `pc` discriminator and a [nonzero random 8-bit diversifier](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/arm64/status.c#L735-L747) stored in `__opaque_flags` field in the thread state.

8-bit diversifier equals to 255 possible valid signatures of a PC. This made brute-force sucks as we cannot deterministically find a valid pointer, only with hopes and dreams that both PC signature and diversifier match. I tried to make it retry the same signature 255 times to crack the diversifier, but that never seems worked either.

### ~~TrollPAC:~~ Hardware breakpoint approach
You know, hardware breakpoint is pretty powerful. It can make a process stop at anywhere we want, so why not make it stop at a `pacia` instruction, overwrite registers storing `pc` and `discriminator`, single step to the next instruction, and finally obtain the signed `br` gadget pointer? This is the legit userspace PAC bypass you have been waiting for.

While this sounds simple, setting this up was not simple at all. In order to be able to set hardware breakpoint, you need to get code execution on another platform process, and since we haven't bypassed PAC in the first place, we have to borrow an arm64 process to do all this. There are 2 candidates:
- Binaries from DeveloperDiskImage: they have arm64 slice. However Apple change the way how DDI is mounted right on iOS 17.0, so this is skipped.
- [UpdateBrainService.xpc](https://updates.cdn-apple.com/2022FallFCS/patches/012-73541/F0A2BDFD-317B-4557-BD18-269079BDB196/com_apple_MobileAsset_MobileSoftwareUpdate_UpdateBrain/f9886a753f7d0b2fc3378a28ab6975769f6b1c26.zip) has a globally signed trust cache
> An example of a globally signed trust cache is shipped with macOS software updates. This trust cache permits a chunk of code within the software update—the update brain—to run with platform privilege. The update brain performs any work to stage the software update that the host system lacks the capacity to perform in a consistent fashion across versions.
<sup><sub>Ignore em-dash — it is copied from [Apple/Trust caches](https://support.apple.com/guide/security/sec7d38fbf97/web)</sub></sup>

So instead of using `UpdateBrainService.xpc` to update to the latest iOS 26 with Liquid Glass etc, we use it here to bypass userland PAC :trollface:

Next, where do we find `pacia`? Turns out dyld uses it very early:
```
    frame #0: 0x000000010001b1f4 dyld`start + 176
dyld`start:
    0x10001b1ec <+168>: adrp   x16, 1
    0x10001b1f0 <+172>: add    x16, x16, #0xfcc ; __Block_byref_object_copy_
->  0x10001b1f4 <+176>: pacia  x16, x8
    0x10001b1f8 <+180>: str    x16, [sp, #0x208]
```

All we need to do now is to:
- Spawn a root process suspended using launch job. At this point, we have not `posix_spawn` the real victim binary yet. This is to make it possible for `UpdateBrainService` to attach to it via `ptrace`.

- Make `UpdateBrainService` attach to the process via `ptrace` and resume it

- When victim process resumes, it will do the Launch Constraint bypass as described above which jumps to victim binary. Since `UpdateBrainService` attached to it earlier, the process will stop at `_dyld_start`, which will fire our exception handler with the victim's task port and thread state.

- Send the task port we got from exception handler to `UpdateBrainService` process via any means like XPC. I borrowed the fake bootstrap server and hooked `bootstrap_look_up` routine to stash the task port. For some reason, it is possible to send a task port that we obtained via exception handler to another process, meanwhile task ports from `task_for_pid` would have the immovable flag set.

- When an attached process execve, it is suspended with `SIGTRAP`. Clear `SIGTRAP` from the victim process with `ptrace(PT_THUPDATE)`

- Set hardware breakpoint at `dyld`'s `pacia` instruction and resume the process

- Once breakpoint hit, overwrite `x16` (aka PC being signed) and `x8` (discriminator) in the victim's thread state. We will use a fixed diversifier `0xAA`

- Single step to the next instruction. I just set hardware breakpoint to the next instruction instead since idk how to get single step working.

- Read `x16`, which is now the signed pointer

- Previously I would make it kill the victim process and respawn it, but now I have made it sign 2 pointers (one is `pacia` itself, another is `br` gadget) and recover x8, x16 and PC in the victim's thread state to resume directly

## Getting `launchd` task port
Now that we have arbitrary code execution in arm64e platform process, let's find a process capable of getting `launchd` task port. In order for a process to get other process's task port, it must be a platform process with `com.apple.system-task-ports.control` entitlement.

Looking over the [entitlements database](https://newosxbook.com/ent.php?osVer=iOS18&exec=com.apple.dt.instruments.dtsecurity) and as @asdfugil suggested, we found `com.apple.dt.instruments.dtsecurity` XPC service, which is very funny judging by its "security" name. How in the world could a security service has the capability to compromise the entire system??? This service is part of Xcode Instruments.

After doing the PAC bypass, all we need to do is to call `task_for_pid` on PID 1 to get `launchd` task port. Now we have tfp1 for iOS 17.0 before GTA 6.

## Modifying launchd memory
After all this we got code execution in platform process and launchd task port. Now we just need to somehow overwrite `launchd` executable path, which is located in `__TEXT` region which may trip codesigning... Fortunately, the `__TEXT` page storing the executable path is outside of the executable code, so we can just reprotect it to writable with `VM_PROT_COPY` and overwrite it.

On iOS 17.0, `launchd` would try to enforce Launch Constraint on itself
```c
int64_t amfi_launch_constraint_set_spawnattr(posix_spawnattr_t* attr, char* bytes, int64_t length) {
  if ( attr && bytes && (uint64_t)(length - 1) <= 0x3FFE )
    return posix_spawnattr_setmacpolicyinfo_np(attr, "AMFI", bytes, length);
  else
    return 22;
}

if ( setenv("XPC_USERSPACE_REBOOTED", "1", 1) != -1 ) {
  v6 = posix_spawnattr_init(&attrs);
  if ( v6 )
    _os_assumes_log(v6);
  v7 = posix_spawnattr_setflags(&attrs, 0x4040);
  if ( v7 )
    _os_assumes_log(v7);
  requirements = xpc_dictionary_create_empty();
  xpc_dictionary_set_bool(requirements, "on-system-volume", 1);
  xpc_dictionary_set_string(requirements, "signing-identifier", "com.apple.xpc.launchd");
  xpc_dictionary_set_int64(requirements, "validation-category", 1);
  v9 = (void *)build_launch_constraints(1, 0, requirements);
  v10 = (void *)serialize_launch_constraints(v9);
  bytes_ptr = xpc_data_get_bytes_ptr(v10);
  length = xpc_data_get_length(v10);
  v13 = amfi_launch_constraint_set_spawnattr(&attrs, bytes_ptr, length);
  if ( v13 )
    goto LABEL_15;
  v14 = _NSGetEnviron();
  v15 = posix_spawn(&pid, "/sbin/launchd", 0LL, &attrs, __argv, *v14);
  v16 = _os_assert_log(v15);
  _os_crash(v16);
  __break(1u);
}
```
At first, I thought we could just rebind `posix_spawnattr_setmacpolicyinfo_np` to a `ret` gadget, but that would require parsing Mach-O etc. Thanks to @wh1te4ever, we found out that we just need to corrupt the `AMFI` string to something else, and it will skip Launch Constraint. Since `AMFI` string is also located far from the executable code page, we can do the same reprotect + overwrite as above.

## Getting further
### amfid codesign bypass
There is no point in doing this given we have CoreTrust bypass, however I was curious if it was still possible to [platformize all binaries via `amfid`](https://github.com/bazad/blanket#bypassing-amfid). Unfortunately, Apple removed relevant code and instead just panic your device when setting `platform` flag, so semi-jailbreak is the peak of this rn.
```diff
 if (signature_valid == 1) {
     if ((unsigned int)_identityMatch(file_path, v197, (const unsigned __int8 *)&v300)) {
         if ((DWORD)isApple) {
-            *(DWORD *)cs_flags |= CS_PLATFORM_BINARY;
-            setAndCheckValidationCategory(*(QWORD *)v262, 1LL, "amfid_made_platform");
+            panic("\"amfid is broken. (%s) (%d) (%d) (%s:%d)\"",
+                file_path, restricted_entitlements,
+                signature_valid, isApple,
+                "AppleMobileFileIntegrity.cpp", 747);
         }
     }
 }
```

### `com.apple.dt.instruments.dtsecurity` as a debugger
I had an idea that if I could `dlopen("/usr/libexec/debugserver")`, I could turn it into a debugger that can attach to platform process. (TODO)

### wen eta nathanlr 17.0
eta now

## Thanks to
- @Siguza for psychicpaper writeup and a complete implementation of exception port method
- @asdfugil
- @wh1te4ever
- @34306 ~~for his time on PAC brute-force~~
