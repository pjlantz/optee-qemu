# CVE-2021-44733: Fuzzing and exploitation of a use-after-free in the Linux kernel TEE subsystem

Recently a use-after-free vulnerability was discovered in the Linux kernel TEE subsystem, up to and including version 5.15.11, and was assigned CVE-2021-44733 [1].

At a first glance it did not seem to be exploitable for several reasons, however after some further analysis of the vulnerable code path and by implementing a crude proof-of-concept exploit it was possible to overwrite a function pointer in the kernel. No privilege escalation payload is presented in this post, however the entire environment for running OPTEE and the exploit is available for further testing, see 'Setting up the environment'.

## Background

A TEE (Trusted Execution Environment) is a trusted OS running in some secure environment, for example, TrustZone on ARM CPUs. A TEE driver handles the details needed to communicate with the TEE. Some of the more important duties of the driver is to provide a generic API towards the TEE based on the Globalplatform TEE Client API specification [3], but also to manage the shared memory between Linux and the TEE. This subsystem can be enabled by configuring `CONFIG_OPTEE` in the kernel configurations for ARM architectures.

The secure world contains the trusted OS denoted OP-TEE OS [4]. On top of this OS it is possible to have so called Trusted Applications (TAs) running which can perform some operations in the isolated environment, see Figure 1.

<p align="center">
  <img src="https://github.com/pjlantz/pjlantz.github.io/raw/master/docs/assets/overview.png?raw=true" alt="TEE overview" width="50%" height="50%"/>
      <br /><em>Figure 1: Overview of TEE - from Linaro's presentation [5]</em>
</p>

The normal world (Linux userspace/kernel) can interact with these applications using client applications (CAs) and the API exposed by the TEE subsystem. A CA can open a session towards a specific TA and invoke functions that the TA implements. Passing of any arguments back and forth between the TA and CA is done using shared memory.
The interaction between a CA and TA using all relevant syscalls is described next.

1. A CA opens up `/dev/tee[0-9]` to communicate with the driver. Note, that for the conventional way of using these APIs, this is done implicitly using the libteec.

2. The shared memory can be registered by the CA using the `IOCTL TEE_IOC_SHM_ALLOC`. This allocates shared memory and returns a file descriptor which user space can use as part of mmap.

3. The next step is to establish a session using the `IOCTL TEE_IOC_OPEN_SESSION` and specifying the uuid for a specific TA. This uuid is hardcoded during the compilation of the TA.

4. In order to invoke any specific function in the TA, the CA invokes this by specifying the identifier of a function along with any input arguments, this is done using `TEE_IOC_INVOKE`.

5. When the CA is finished with all requests, the session can be closed using `TEE_IOC_CLOSE_SESSION`. 

<p align="center">
  <img src="https://github.com/pjlantz/pjlantz.github.io/raw/master/docs/assets/overview2.png?raw=true" alt="Session between CA and TA" width="50%" height="50%"/>
      <br /><em>Figure 2: Session between CA and TA - from Linaro's presentation [5]</em>
</p>

Much of the communication between clients and the TEE is opaque to the driver. The main job for the driver is to manage the context, receive requests from the clients, forward them to the TEE and send back the results [2].

## Fuzzing of the TEE driver
CVE-2021-44733 was discovered using fuzzing with syzkaller. The description file used for this is provided below. Note that `ioctl$TEE_SHM_REGISTER_FD` is only part of Linaro (maintainers) kernel tree and not in upstream. The environment provided in 'Setting up the environment' could be used for fuzzing if configured properly according to syzkaller documentation [6]

```
#include <uapi/linux/tee.h>
  
resource fd_tee0[fd]
resource session_resource[int32]
  
openat$tee0(fd const[AT_FDCWD], dev ptr[in, string["/dev/tee0"]], flags flags[open_flags], mode flags[open_mode]) fd_tee0
ioctl$TEE_OPEN_SESSION(fd fd_tee0, cmd const[0x8010a402], arg ptr[inout, tee_ioctl_buf_data_session])
ioctl$TEE_INVOKE(fd fd_tee0, cmd const[0x8010a403], arg ptr[inout, tee_ioctl_buf_data_invoke])
ioctl$TEE_CANCEL(fd fd_tee0, cmd const[0x8008a404], arg ptr[in, tee_ioctl_buf_data_cancel])
ioctl$TEE_CLOSE_SESSION(fd fd_tee0, cmd const[0x8004a405], arg ptr[in, tee_ioctl_buf_data_close])
ioctl$TEE_VERSION(fd fd_tee0, cmd const[0x800ca400], arg ptr[out, tee_ioctl_buf_data_version])
ioctl$TEE_SHM_ALLOC(fd fd_tee0, cmd const[0xc010a401], arg ptr[inout, tee_ioctl_buf_data_shm_alloc])
ioctl$TEE_SHM_REGISTER(fd fd_tee0, cmd const[0xc018a409], arg ptr[inout, tee_ioctl_buf_data_shm_register])
ioctl$TEE_SHM_REGISTER_FD(fd fd_tee0, cmd const[0xc018a408], arg ptr[inout, tee_ioctl_buf_data_shm_register_fd])
ioctl$TEE_SUPPL_RECV(fd fd_tee0, cmd const[0x8010a406], arg ptr[inout, tee_ioctl_buf_suppl_recv])
ioctl$TEE_SUPPL_SEND(fd fd_tee0, cmd const[0x8010a407], arg ptr[inout, tee_ioctl_buf_suppl_send])
  
# COMMON
#=======================================================
  
define TEE_IOCTL_UUID_LEN   16
  
tee_ioctl_param_struct {
    attr    flags[TEE_IOCTL_PARAM_ATTR_TYPE, int64]
    a       int64
    b       int64
    c       int64
}
  
TEE_IOCTL_PARAM_ATTR_TYPE = 0, 1, 2, 3, 5, 6, 7
TEE_LOGIN = 0, 1, 2, 4, 5, 6
  
 
  
# OPEN SESSION
#=======================================================
  
tee_ioctl_buf_data_session {
    buf_ptr ptr64[inout, tee_ioctl_open_session_struct]
    buf_len len[buf_ptr, int64]
}
  
tee_ioctl_open_session_struct {
    uuid        array[int8, TEE_IOCTL_UUID_LEN] (in)
    clnt_uuid   array[int8, TEE_IOCTL_UUID_LEN] (in)
    clnt_login  flags[TEE_LOGIN, int32]         (in)
    cancel_id   int32                           (in)
    session     session_resource                (out)
    ret         int32                           (out)
    ret_origin  int32                           (out)
    num_params  len[params, int32]              (in)
    params      array[tee_ioctl_param_struct]   (in)
}
  
 
  
# INVOKE
#=======================================================
  
tee_ioctl_buf_data_invoke {
    buf_ptr ptr64[inout, tee_ioctl_invoke_struct]
    buf_len len[buf_ptr, int64]
}
  
tee_ioctl_invoke_struct {
    func        int32                           (in)
    session     session_resource                (in)
    cancel_id   int32                           (in)
    ret         int32                           (out)
    ret_origin  int32                           (out)
    num_params  len[params, int32]              (in)
    params      array[tee_ioctl_param_struct]   (in)
}
  
 
  
# CANCEL SESSION
#=======================================================
  
tee_ioctl_buf_data_cancel {
    cancel_id   int32               (in)
    session     session_resource    (in)
}
  
 
  
# CLOSE SESSION
#=======================================================
  
tee_ioctl_buf_data_close {
    session session_resource    (in)
}
  
 
  
# VERSION
#=======================================================
  
tee_ioctl_buf_data_version {
    impl_id     int32   (out)
    impl_caps   int32   (out)
    gen_caps    int32   (out)
}
  
 
  
# SHM ALLOC
#=======================================================
  
tee_ioctl_buf_data_shm_alloc {
    size        int64               (inout)
    flags       const[0, int32]     (inout)
    id          int32               (out)
}
  
 
  
# SHM REGISTER
#=======================================================
  
tee_ioctl_buf_data_shm_register {
    addr    int64               (in)
    length  int64               (inout)
    flags   const[0, int32]     (inout)
    id      int32               (out)
}
  
 
  
# SHM REGISTER FD
#=======================================================
  
tee_ioctl_buf_data_shm_register_fd {
    fd      int64               (in)
    size    int64               (out)
    flags   const[0, int32]     (in)
    id      int32               (out)
} [align[8]]
  
 
  
# SUPPLICANT RECV
#=======================================================
  
tee_ioctl_buf_suppl_recv {
    func        int32                           (in)
    num_params  len[params, int32]              (inout)
    params      array[tee_ioctl_param_struct]   (inout)
}
  
 
  
# SUPPLICANT SEND
#=======================================================
  
tee_ioctl_buf_suppl_send {
    ret         int32                           (out)
    num_params  len[params, int32]              (in)
    params      array[tee_ioctl_param_struct]   (in)
}
```
During fuzzing, the crash that caught the attention was related to a use-after-free of a task_struct object while a mutex was held:

```
==================================================================
BUG: KASAN: use-after-free in __mutex_lock.constprop.0+0x118c/0x11c4
Read of size 4 at addr 863b0714 by task optee_example_r/244
 
CPU: 0 PID: 244 Comm: optee_example_r Tainted: G      D           5.14.0 #151
Hardware name: Generic DT based system
[<8012b204>] (unwind_backtrace) from [<8011f460>] (show_stack+0x20/0x24)
[<8011f460>] (show_stack) from [<81cf0108>] (dump_stack_lvl+0x5c/0x68)
[<81cf0108>] (dump_stack_lvl) from [<80650f04>] (print_address_description.constprop.0+0x38/0x304)
[<80650f04>] (print_address_description.constprop.0) from [<80651548>] (kasan_report+0x1c0/0x1dc)
[<80651548>] (kasan_report) from [<81d0a9b4>] (__mutex_lock.constprop.0+0x118c/0x11c4)
[<81d0a9b4>] (__mutex_lock.constprop.0) from [<81d0ada4>] (mutex_lock+0x128/0x13c)
[<81d0ada4>] (mutex_lock) from [<817424b0>] (tee_shm_release+0x4b0/0x6cc)
[<817424b0>] (tee_shm_release) from [<81303674>] (dma_buf_release+0x1b8/0x2f0)
[<81303674>] (dma_buf_release) from [<806d5ac0>] (__dentry_kill+0x4c4/0x678)
[<806d5ac0>] (__dentry_kill) from [<806d8a68>] (dput+0x630/0xba4)
[<806d8a68>] (dput) from [<8067d890>] (__fput+0x3b4/0x900)
[<8067d890>] (__fput) from [<801dd1d8>] (task_work_run+0x15c/0x230)
[<801dd1d8>] (task_work_run) from [<80172b70>] (do_exit+0x103c/0x3770)
[<80172b70>] (do_exit) from [<80179aec>] (do_group_exit+0x134/0x3ac)
[<80179aec>] (do_group_exit) from [<801a7658>] (get_signal+0x7d8/0x2f28)
[<801a7658>] (get_signal) from [<8011dea4>] (do_work_pending+0x984/0x154c)
[<8011dea4>] (do_work_pending) from [<801000d0>] (slow_work_pending+0xc/0x20)
Exception stack(0x85743fb0 to 0x85743ff8)
3fa0:                                     00023108 00000080 00000000 00000000
3fc0: 66bca2d0 66bca2d0 66bca2d0 000000f0 66bca2d0 66bca340 00000000 6ec00b0c
3fe0: 66bc9cc8 66bc9cb8 00011655 66c80c20 000e0130 00023108
 
Allocated by task 242:
 set_alloc_info+0x48/0x50
 __kasan_slab_alloc+0x48/0x58
 kmem_cache_alloc+0x14c/0x314
 copy_process+0x2014/0x7b18
 kernel_clone+0x244/0xfc8
 sys_clone+0xc8/0xec
 ret_fast_syscall+0x0/0x58
 0x6ec00a10
 
Freed by task 67:
 kasan_set_track+0x28/0x30
 kasan_set_free_info+0x20/0x34
 __kasan_slab_free+0xdc/0x108
 kmem_cache_free+0x80/0x394
 __put_task_struct+0x2b4/0x35c
 delayed_put_task_struct+0x104/0x384
 rcu_core+0x91c/0x2a68
 __do_softirq+0x2fc/0xfb8
 
Last potentially related work creation:
 kasan_record_aux_stack+0xb8/0xc0
 call_rcu+0x9c/0xfd0
 put_task_struct_rcu_user+0x9c/0xbc
 finish_task_switch+0x534/0xa10
 __schedule+0x934/0x1adc
 schedule_idle+0x9c/0x120
 do_idle+0x2ec/0x434
 cpu_startup_entry+0x18/0x1c
 start_kernel+0x3ec/0x430
 
The buggy address belongs to the object at 863b0700
 which belongs to the cache task_struct of size 1664
The buggy address is located 20 bytes inside of
 1664-byte region [863b0700, 863b0d80)
The buggy address belongs to the page:
page:f09c9565 refcount:1 mapcount:0 mapping:00000000 index:0x0 pfn:0x463b0
head:f09c9565 order:3 compound_mapcount:0 compound_pincount:0
flags: 0x10200(slab|head|zone=0)
raw: 00010200 00000000 00000122 82802e00 00000000 80120012 ffffffff 00000001
page dumped because: kasan: bad access detected
 
Memory state around the buggy address:
 863b0600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 863b0680: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
>863b0700: fa fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
                 ^
 863b0780: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
 863b0800: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
==================================================================
```

This was triggered by closing all file descriptors from `TEE_IOC_SHM_ALLOC` while a different thread opens a session towards in our case, a non-existing TA. Syzkaller managed to reproduce it and by experimenting with the reproducer code and slightly delaying the call to `TEE_IOC_OPEN_SESSION`, a different UAF occurred for an object belonging to the kmalloc-64 cache:

```

==================================================================
BUG: KASAN: use-after-free in tee_shm_put+0x8c/0x98
Read of size 4 at addr 86467020 by task optee_example_h/216
 
CPU: 0 PID: 216 Comm: optee_example_h Not tainted 5.14.0 #21
Hardware name: Generic DT based system
[<80122584>] (unwind_backtrace) from [<80117fd4>] (show_stack+0x10/0x14)
[<80117fd4>] (show_stack) from [<819d57a0>] (dump_stack_lvl+0x40/0x4c)
[<819d57a0>] (dump_stack_lvl) from [<819ced74>] (print_address_description.constprop.0+0x5c/0x2d8)
[<819ced74>] (print_address_description.constprop.0) from [<805a12c4>] (kasan_report+0x1b4/0x1d0)
[<805a12c4>] (kasan_report) from [<814cc6b0>] (tee_shm_put+0x8c/0x98)
[<814cc6b0>] (tee_shm_put) from [<814c9b2c>] (tee_ioctl+0x1578/0x2e44)
[<814c9b2c>] (tee_ioctl) from [<806038ec>] (sys_ioctl+0x918/0x1e70)
[<806038ec>] (sys_ioctl) from [<80100060>] (ret_fast_syscall+0x0/0x58)
Exception stack(0x86417fa8 to 0x86417ff0)
7fa0:                   00000080 00000000 00000003 8010a402 200001c0 00000003
7fc0: 00000080 00000000 00423018 00000036 66c562d0 66c55e10 66c562d0 6ebebafc
7fe0: 66c55cb0 66c55ca0 004114bd 66cebd72
 
Allocated by task 216:
 tee_shm_alloc+0x15c/0x7e8
 tee_ioctl+0x8d0/0x2e44
 sys_ioctl+0x918/0x1e70
 ret_fast_syscall+0x0/0x58
 0x66c55ca0
 
Freed by task 215:
 kasan_set_free_info+0x20/0x34
 __kasan_slab_free+0xdc/0x108
 kfree+0x98/0x294
 tee_shm_release+0x1dc/0x610
 dma_buf_release+0x180/0x2a0
 __dentry_kill+0x488/0x6ac
 __fput+0x2f0/0x7b4
 task_work_run+0x178/0x230
 do_work_pending+0xaf8/0x10a8
 slow_work_pending+0xc/0x20
 0x66d5bd16
 
The buggy address belongs to the object at 86467000
 which belongs to the cache kmalloc-64 of size 64
The buggy address is located 32 bytes inside of
 64-byte region [86467000, 86467040)
The buggy address belongs to the page:
page:(ptrval) refcount:1 mapcount:0 mapping:00000000 index:0x0 pfn:0x46467
flags: 0x200(slab|zone=0)
raw: 00000200 00000000 00000122 82401200 00000000 00200020 ffffffff 00000001
page dumped because: kasan: bad access detected
 
Memory state around the buggy address:
 86466f00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 86466f80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
>86467000: fa fb fb fb fb fb fb fb fc fc fc fc fc fc fc fc
                       ^
 86467080: fa fb fb fb fb fb fb fb fc fc fc fc fc fc fc fc
 86467100: fa fb fb fb fb fb fb fb fc fc fc fc fc fc fc fc
==================================================================
```
This vulnerability was discovered by fuzzing the TEE driver without any session being established with an existing TA running on the system. This could be further extended with so called pseudo syscalls in syzkaller in order to setup and initiate a session towards some TA.

## Root cause analysis
The conclusion is a design issue with the lifetime tracking of a `tee_shm:dmabuf` object. The driver is designed to let userspace keep the one-and-only reference count after a call to `tee_ioctl_shm_alloc()`.

It is assumed that if the object still is found in the driver’s IDR object, then the reference to the dmabuf is still valid and its reference count can be incremented. It turns out this is only partially true. The dmabuf memory is still owned by the dmabuf driver, but it may be in the process of being destroyed and that cannot be stopped by making the reference count non-zero again.

The scenario that triggers the problem is a multi-threaded application where one thread closes the dmabuf file-descriptor at the same time that another thread makes a call to the IOCTL command `TEE_IOC_OPEN_SESSION` or `TEE_IOC_INVOKE` referencing that shared memory.

Tracing the destruction of the dmabuf when user-space closes the fd will run this code in the kernel:

1. `fput()`

2. `fput_many()`  >> File reference count reaches zero. Race window opens.

3. `[task_work gets scheduled]`

4. `__fput`

5. `dput`

6. `dma_buf_release`

7. `tee_shm_release`

     8. `mutex_lock(teedev->mutex)`

     9. `idr_remove(teedev->idr, shm->id)` >> Now the shm object can no longer be referenced from userspace. Race window closes.

     10. `mutex_unlock()`
  
This means that the IDR table  and its mutex lock cannot guarantee that the dmabuf and corresponding `tee_shm` is still alive. A process racing `fput()` by calling `tee_shm_get_from_id()` can get a reference to a shm that is about to go dead.

```
/**
 * tee_shm_get_from_id() - Find shared memory object and increase reference
 * count
 * @ctx:    Context owning the shared memory
 * @id:     Id of shared memory object
 * @returns a pointer to 'struct tee_shm' on success or an ERR_PTR on failure
 */
struct tee_shm *tee_shm_get_from_id(struct tee_context *ctx, int id)
{
    struct tee_device *teedev;
    struct tee_shm *shm;
 
    if (!ctx)
        return ERR_PTR(-EINVAL);
 
    teedev = ctx->teedev;
    mutex_lock(&teedev->mutex);
    shm = idr_find(&teedev->idr, id);
    if (!shm || shm->ctx != ctx)
        shm = ERR_PTR(-EINVAL);
    else if (shm->flags & TEE_SHM_DMA_BUF)
        get_dma_buf(shm->dmabuf);
    mutex_unlock(&teedev->mutex);
    return shm;
}
```

## Exploiting the UAF
In order to exploit this, a reallocation must be made after the object has been free'd and before triggering the UAF. After the call to `tee_shm_get_from_id()`, the function `tee_shm_put()` (for which the second UAF crash from syzkaller occurs) is called which dereferences the `tee_shm:dmabuf` object used as input argument to `dma_buf_put()`.

```
/**
 * tee_shm_put() - Decrease reference count on a shared memory handle
 * @shm:    Shared memory handle
 */
void tee_shm_put(struct tee_shm *shm)
{
    if (shm->flags & TEE_SHM_DMA_BUF)
        dma_buf_put(shm->dmabuf);
}
EXPORT_SYMBOL_GPL(tee_shm_put);
```
The `tee_shm` object could be reallocated before the UAF as it belongs to the kmalloc-64 cache. It would have to be reallocated with:

1. fake `tee_shm`, `tee_shm:dmabuf`, `dma_buf:file` objects 
2. set `file->f_count = 1`
3. craft a `file:file_operations` object that has the `fasync` function pointer set to an arbitrary address

This function is then invoked in `__fput()` after the call to `dma_buf_put()` when `file->f_count` reaches zero. 

PAN (Privileged Access Never) mitigates this as fake objects must be referenced in userspace memory in order to set an arbitrary function pointer in the `file:f_ops` structure. Therefore `CONFIG_CPU_SW_DOMAIN_PAN` must be disabled for this to work which it is in the provided environment. There are some open questions left as whether PAN can be bypassed in this vulnerability, e.g., using ret2dir. 

Also, in order to perform a successful reallocation of the free'd shm object, the IOCTL call `TEE_IOC_OPEN_SESSION` or `TEE_IOC_INVOKE` must be preemted by a thread performing the file descriptor close and heap spraying thread that fills the kmalloc-64 cache. For this to work the kernel must be configured with `CONFIG_PREEMPT`. In this PoC the heap spray from Nicolas Fabretti's blog post [7] was utilized based on blocking `sendmsg()`. 

To summarize, the issue in regards to exploitation is that both the free and UAF must occur within the same system call. In addition to this, freeing is hard to trigger as it is requires racing within the syscall. After freeing, the time between it and the actual UAF is a small time window where a heap spray must be performed to reallocate the free'd object. The following Figure shows the threads involved in the exploit code and their role.


<p align="center">
  <img src="https://github.com/pjlantz/pjlantz.github.io/raw/master/docs/assets/Threads.png?raw=true" alt="Threads involved" width="50%" height="50%"/>
       <br /><em>Figure 3: Threads involved in the exploit code</em>
</p>

  
Three type of threads are running continuously. In order to preempt the system calling thread, it is running with the lowest possible priority, `SCHED_IDLE` while the others have the priority set to `SCHED_OTHER`. Because we are using blocking `sendmsg()`, each spray attempt must run in its own thread and it must run on the same CPU core that triggers the UAF since each core keeps their own kmalloc caches. There are also a number of freeing threads that close the file descriptor from the shared memory allocation in step 1b). Full source code for this UAF trigger and function pointer overwrite can be found at [10].

## Setting up the new environment
To reproduce the environment with a vulnerable kernel and OPTEE, it can be cloned from the following repository and built using:

```
$ mkdir optee-qemu && cd optee-qemu
$ repo init -u https://github.com/pjlantz/optee-qemu.git
$ repo sync
$ cd build
$ make toolchains -j2
$ make run
```
After successful build, it will spawn three consoles, one for QEMU - press 'c' in the QEMU console in order to boot. A second console shows output from the secure world and the final one will boot into Linux. Login as root (no password).

Run the exploit code until the `fasync` function pointer of the `file_operations` structure is set to `0x22000000`. 

```
until optee_exploit | grep "0x22000000" /var/log/messages; do sleep 0.01; done
```

This will stop due to Privileged execute-never (PXN) blocking the execution at `PC=0x22000000`. From here on, exploitation strategies can vary depending on the kernel version, but it might be possible to execute a kernel ROP and do stack pivoting, or make vDSO area writable and place the payload there. It might also be interesting for future work to investigate whether PAN can be bypassed using ret2dir and some physmap spraying. PAN can be enabled in the kernel by setting `CONFIG_CPU_SW_DOMAIN_PAN=y` in `linux/.config`. On real hardware, it is enabled by default on ARMv8.1 and AArch64, for ARMv7 and AArch32 it is possible to have software emulated PAN using this setting [8]. 

**Note**: This exploit is not very well optimized and may occasionally hang the driver if it manage to free the shared memory object too early, in this case PC will be at `tee_shm_get_from_id()`. If this happens, issue a `system_reset` in the QEMU console to reboot the environment.

## Acknowledgments
Thanks to Lars Persson at Axis Communications for help with the root cause analysis and Jens Wiklander at Linaro and maintainer of the TEE subsystem for a smooth communication and quick resolving of this issue [9].

## References 

[1] CVE-2021-44733 - https://nvd.nist.gov/vuln/detail/CVE-2021-44733

[2] TEE subsystem - https://www.kernel.org/doc/html/latest/staging/tee.html

[3] Globalplatform TEE API - https://globalplatform.org/specs-library/?filter-committee=tee

[4] OP-TEE OS - https://github.com/OP-TEE/optee_os

[5] BKK16-110: A Gentle Introduction to Trusted Execution and OP-TEE - https://connect.linaro.org/resources/bkk16/bkk16-110/

[6] Syzkaller - https://github.com/google/syzkaller 

[7] Lexfo's security blog, by Nicolas Fabretti: CVE-2017-11176: A step-by-step Linux Kernel exploitation - https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part3.html

[8] Linux Kernel Security Subsystem: Exploit Methods/Userspace data usage - http://kernsec.org/wiki/index.php/Exploit_Methods/Userspace_data_usage

[9] [PATCH v2] tee: handle lookup of shm with reference count 0 - https://lore.kernel.org/lkml/20211215092501.1861229-1-jens.wiklander@linaro.org/T/ 

[10] Proof of concept exploit - https://github.com/pjlantz/optee_examples/tree/master/exploit/host
