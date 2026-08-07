# New CWEs for Transient Execution

A proposal by Intel, in collaboration with MITRE and the CWE community

## Motivation and Overview

Common Weakness Enumeration (CWE) is "a community-developed list of
common software and hardware weakness types that have security
ramifications" \[1\]. Common Vulnerability Enumeration (CVE) is a list
of publicly known vulnerabilities. Each CVE is an instance of a CWE. For
example,
[CVE-2021-43618](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-43618)
is "GNU Multiple Precision Arithmetic Library (GMP) through 6.2.1 has an
`mpz/inp_raw.c` integer overflow and resultant buffer overflow via
crafted input, leading to a segmentation fault on 32-bit platforms."
This CVE is an instance of
[CWE-787](https://cwe.mitre.org/data/definitions/787.html), whose
description reads "The software writes data past the end, or before the
beginning, of the intended buffer."

Whenever an organization (such as Intel) issues a CVE for a new
transient execution attack, its description is expected to borrow
language from an existing CWE. The following table summarizes CWEs that
pertain to transient execution attacks.

| CWE                                                      | Title                                                                             | Description                                                                                                                                                                               |
| -------------------------------------------------------- | --------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [1037](https://cwe.mitre.org/data/definitions/1037.html) | Processor Optimization Removal or Modification of Security-critical Code          | The developer builds a security-critical protection mechanism into the software, but the processor optimizes the execution of the program such that the mechanism is removed or modified. |
| [1264](https://cwe.mitre.org/data/definitions/1264.html) | Hardware Logic with Insecure De-Synchronization between Control and Data Channels | The hardware logic for error handling and security checks can incorrectly forward data before the security check is complete.                                                             |
| [1303](https://cwe.mitre.org/data/definitions/1303.html) | Non-Transparent Sharing of Microarchitectural Resources                           | Hardware resources shared across execution contexts (e.g., caches and branch predictors) can violate the expected architecture isolation between contexts.                                |
| [1342](https://cwe.mitre.org/data/definitions/1342.html) | Information Exposure through Microarchitectural State after Transient Execution   | The processor does not properly clear microarchitectural state after incorrect microcode assists or speculative execution, resulting in transient execution.                              |

These existing CWEs do not address the root causes of transient
execution attacks, and therefore do not suffice to characterize them.
For example, consider
[CVE-2017-5753](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5753)
(Bounds Check Bypass, or BCB):

  - Although BCB can affect conditional branches that do serve as
    "security-critical protection mechanisms" (for example, in
    software sandboxes), BCB can also affect branches that serve a
    functional purpose, such as dynamic type checking \[2\]. Therefore
    CWE-1037 is too narrow.

  - The conditional branch instructions affected by BCB are not
    "hardware logic for error handling and security checks." Hence
    CWE-1264 does not apply.

  - BCB can be exploited over a network \[3\] without shared hardware
    resources, and therefore CWE-1303 does not apply.

  - CWE-1342 implies that the processor should be clearing
    microarchitectural state, which is impractical or infeasible for
    many vulnerabilities, including BCB.

This document aims to define **five** new CWEs that address the root
causes of transient execution attacks, and with language that is
sufficiently generic to benefit the entire CWE community.

## New CWE Proposals

### CWE-A: Exposure of Sensitive Information during Transient Execution

#### Description

A processor event or prediction may allow incorrect operations (or
correct operations with incorrect data) to execute transiently,
potentially exposing data over a covert channel.

#### Extended Description

When operations execute but do not commit to the processor’s
architectural state, this is commonly referred to as *transient
execution*. This behavior can occur when the processor mis-predicts an
outcome (such as a branch target), or when a processor event (such as an
exception or microcode assist, etc.) is handled after younger operations
have already executed. Operations that execute transiently may exhibit
observable discrepancies
([CWE-203](https://cwe.mitre.org/data/definitions/203.html)) in covert
channels such as data caches. Observable discrepancies of this kind can
be detected and analyzed using timing or power analysis techniques,
which may allow an attacker to infer information about the operations
that executed transiently. For example, the attacker may be able to
infer confidential data that was accessed or used by those operations.

Transient execution weaknesses may be exploited using one of two
methods. In the first method, the attacker generates a code sequence
that exposes data through a covert channel when it is executed
transiently (the attacker must also be able to trigger transient
execution). Some transient execution weaknesses can only expose data
that is accessible within the attacker’s processor context. For example,
an attacker executing code in a software sandbox may be able to use a
transient execution weakness to expose data within the same address
space, but outside of the attacker’s sandbox. Other transient execution
weaknesses can expose data that is architecturally inaccessible, that
is, data protected by hardware-enforced boundaries such as page tables
or privilege rings. These weaknesses are the subject of CWE-B.

In the second exploitation method, the attacker first identifies a code
sequence in a victim program that, when executed transiently, can expose
data that is architecturally accessible within the victim’s processor
context. For instance, the attacker may search the victim program for
code sequences that resemble a bounds-check bypass sequence (see
Demonstrative Example 1). If the attacker can trigger a mis-prediction
of the conditional branch and influence the index of the out-of-bounds
array access, then the attacker may be able to infer the value of
out-of-bounds data by monitoring observable discrepancies in a covert
channel.

#### Modes of Introduction

| Phase                   | Note                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Architecture and Design | This weakness can be introduced when a computing unit (such as a CPU, GPU, accelerator, or any other processor) uses out-of-order execution, speculation, or any other microarchitectural feature that can allow microarchitectural operations to execute without committing to architectural state.                                                                                                                                                                                                                                        |
| Implementation          | This weakness can be introduced when sandboxes or managed runtimes are not properly isolated by using hardware-enforced boundaries. Developers of sandbox or managed runtime software should exercise caution when relying on software techniques (such as bounds checking) to prevent code in one sandbox from accessing confidential data in another sandbox. For example, an attacker sandbox may be able to trigger a processor event or mis-prediction in a manner that allows it to transiently read a victim sandbox’s private data. |

#### Potential Mitigations

##### Phase: Architecture and Design

The hardware designer can attempt to prevent transient execution from
causing observable discrepancies in specific covert channels.  
**Effectiveness: Limited**  
**Note:** This technique has many pitfalls. For example, InvisiSpec was
an early attempt to mitigate this weakness by blocking
"micro-architectural covert and side channels through the
multiprocessor data cache hierarchy due to speculative loads" \[REF-1\].
Commodity processors and SoCs have many covert and side channels that
exist outside of the data cache hierarchy. Even when some of these
channels are blocked, others (such as execution ports \[REF-2\]) may
allow an attacker to infer confidential data. Mitigation strategies that
attempt to prevent transient execution from causing observable
discrepancies also have other pitfalls, for example, see \[REF-3\].

##### Phase: Requirements

Processor designers may expose instructions or other architectural
features that allow software to mitigate the effects of transient
execution, but without disabling predictors. These features may also
help to limit opportunities for data exposure.  
**Effectiveness: Moderate  
Note:** Instructions or features that constrain transient execution or
suppress its side effects may impact performance.

Processor designers may expose registers (for example, control registers
or model-specific registers) that allow privileged and/or user software
to disable specific predictors or other hardware features that can cause
confidential data to be exposed during transient execution.  
**Effectiveness: Limited  
Note:** Disabling specific predictors or other hardware features may
result in significant performance overhead.

Processor designers, system software vendors, or other agents may choose
to restrict the ability of unprivileged software to access to
high-resolution timers that are commonly used to monitor covert
channels.  
**Effectiveness: Defense in Depth**  
**Note:** Specific software algorithms can be used by an attacker to
compensate for a lack of a high-resolution time source \[REF-4\].

##### Phase: Build and Compilation

Isolate sandboxes or managed runtimes in separate address spaces
(separate processes). For examples, see \[REF-5\].  
**Effectiveness: High**

Include serialization instructions (for example, LFENCE) that prevent
processor events or mis-predictions prior to the serialization
instruction from causing transient execution after the serialization
instruction. For some weaknesses, a serialization instruction can also
prevent a processor event or a mis-prediction from occurring after the
serialization instruction (for example,
[CVE-2018-3639](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3639)
can allow a processor to predict that a load will not depend on an older
store; a serialization instruction between the store and the load may
allow the store to update memory and prevent the prediction from
happening at all).  
**Effectiveness: Moderate**  
**Note:** When used to comprehensively mitigate a transient execution
weakness (for example, by inserting an LFENCE after every instruction in
a program), serialization instructions can introduce significant
performance overhead. On the other hand, when used to mitigate only a
relatively small number of high-risk code sequences, serialization
instructions may have a low or negligible impact on performance.

Use control-flow integrity (CFI) techniques to constrain the behavior of
instructions that redirect the instruction pointer, such as indirect
branch instructions.  
**Effectiveness: Moderate**  
**Note:** Some CFI techniques may not be able to constrain transient
execution, even though they are effective at constraining architectural
execution. Or they may be able to provide some additional protection
against a transient execution weakness, but without comprehensively
mitigating the weakness. For example, Clang-CFI provides strong
architectural CFI properties and can make some transient execution
weaknesses more difficult to exploit \[REF-6\].

If the weakness is exposed by a single instruction (or a small set of
instructions), then the compiler (or JIT, etc.) can be configured to
prevent the affected instruction(s) from being generated, and instead
generate an alternate sequence of instructions that is not affected by
the weakness. One prominent example of this mitigation is retpoline
(\[REF-7\]).  
**Effectiveness: Limited**  
**Note:** This technique may only be effective for software that is
compiled with this mitigation. For some transient execution weaknesses,
this technique may not be sufficient to protect software that is
compiled without the affected instruction(s). For example, see CWE-B.

Use software techniques that can mitigate the consequences of transient
execution. For example, address masking can be used in some
circumstances to prevent out-of-bounds transient reads.  
**Effectiveness: Limited**  
**Note:** Address masking and related software mitigation techniques have
been used to harden specific code sequences that could potentially be
exploited via transient execution. For example, the Linux kernel makes
limited use of manually inserted address masks to mitigate bounds-check
bypass \[REF-8\]. Compiler-based techniques have also been used to
automatically harden software \[REF-9\].

Use software techniques (including the use of serialization
instructions) that are intended to reduce the number of instructions
that can be executed transiently after a processor event or
misprediction.  
**Effectiveness: Incidental  
Note:** Some transient execution weaknesses can be exploited even if a
single instruction is executed transiently after a processor event or
mis-prediction. This mitigation strategy has many other pitfalls that
prevent it from eliminating this weakness entirely. For example, see
\[REF-10\].

##### Phase: Documentation

If a hardware feature can allow incorrect operations (or correct
operations with incorrect data) to execute transiently, the hardware
designer may opt to disclose this behavior in architecture
documentation. This documentation can inform users about potential
consequences and effective mitigations.  
**Effectiveness: High**

#### Detection Methods

##### Manual Analysis

This weakness can be detected in hardware by manually inspecting
processor specifications. Features that exhibit this weakness may
include microarchitectural predictors, access control checks that occur
out-of-order, or any other features that can allow operations to execute
without committing to architectural state. Academic researchers have
demonstrated that new hardware weaknesses can be discovered by
exhaustively analyzing a processor’s machine clear (or nuke) conditions
(\[REF-11\]).

##### Fuzzing - Hardware

Academic researchers have demonstrated that this weakness can be
detected in hardware using software fuzzing tools that treat the
underlying hardware as a black box (\[REF-12\]).

##### Fuzzing - Software

Academic researchers have demonstrated that this weakness can be
detected in software using software fuzzing tools (\[REF-13\]).

##### Automated Static Analysis

A variety of automated static analysis tools can identify potentially
exploitable code sequences in software. These tools may perform the
analysis on source code, on binary code, or on an intermediate code
representation (for example, during compilation).

##### Automated Analysis

Software vendors can release tools that detect presence of known
weaknesses on a processor. For example, some of these tools can attempt
to transiently execute a vulnerable code sequence and detect whether
code successfully leaks data in a manner consistent with the weakness
under test. Alternatively, some hardware vendors provide enumeration for
the presence of a weakness (or lack of a weakness). These enumeration
bits can be checked and reported by system software. For example, Linux
supports these checks for many commodity processors:

    $ cat /proc/cpuinfo | grep bugs | head -n 1
    bugs            : cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs taa itlb_multihit srbds mmio_stale_data retbleed

#### Common Consequences

| Scope           | Impact                        | Likelihood |
| --------------- | ----------------------------- | ---------- |
| Confidentiality | Technical Impact: Read Memory | Medium     |

#### Applicable Platforms

##### Languages

Class: Not Language-Specific *(Undetermined Prevalence)*

##### Operating Systems

Class: Not OS-Specific *(Undetermined Prevalence)*

##### Architectures

Class: Not Architecture-Specific *(Undetermined Prevalence)*

##### Technologies

Class: Not Technology-Specific *(Undetermined Prevalence)*

#### Demonstrative Examples

##### Example 1

Secure programs perform bounds checking before accessing an array if the
source of the array index is provided by an untrusted source such as
user input. In the code below, data from `array1` will not be accessed
if `x` is out of bounds. However, if this code executes on a processor
that performs conditional branch prediction the outcome of the `if`
statement could be mis-predicted and the access on the next line will
occur with a value of `x` that can point to an out-of-bounds location
(within the program’s memory).

Even though the processor does not commit the architectural effects of
the mis-predicted branch, the memory accesses alter data cache state,
which is not rolled back after the branch is resolved. The cache state
can reveal `array1[x]` thereby providing a mechanism to recover the data
value located at address `array1 + x`.

    Example Language: C
    if (x < array1_size)
        y = array2[array1[x] * 4096]; 

Code snippet is from \[REF-14\].

##### Example 2

Some managed runtimes or just-in-time (JIT) compilers may overwrite
recently executed code with new code. When the instruction pointer
enters the new code, the processor may inadvertently execute the stale
code that had been overwritten. This can happen, for instance, when the
processor issues a store that overwrites a sequence of code, but the
processor fetches and executes the (stale) code before the store updates
memory. Similar to the first example, the processor does not commit the
stale code’s architectural effects, though microarchitectural side
effects can persist. Hence, confidential information accessed or used by
the stale code may be inferred via an observable discrepancy in a covert
channel.

This vulnerability is described in more detail in \[REF-11\].

#### Observed Examples

| Reference                                                       | Description                                                                                                                                                                 |
| --------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [CVE-2017-5753](https://www.cve.org/CVERecord?id=CVE-2017-5753) | Microarchitectural conditional branch predictors may allow operations to execute transiently after a misprediction, potentially exposing data over a covert channel.        |
| [CVE-2021-0089](https://www.cve.org/CVERecord?id=CVE-2021-0089) | A machine clear triggered by self-modifying code may allow incorrect operations to execute transiently, potentially exposing data over a covert channel.                    |
| [CVE-2022-0002](https://www.cve.org/CVERecord?id=CVE-2022-0002) | Microarchitectural indirect branch predictors may allow incorrect operations to execute transiently after a misprediction, potentially exposing data over a covert channel. |

#### Relationships

  - Parent of CWE-B

  - Parent of CWE-C

  - Parent of CWE-D

  - Parent of CWE-E

#### References

\[REF-1\] Mengjia Yan, Jiho Choi, Dimitrios Skarlatos, Adam Morrison,
Christopher W. Fletcher, Josep Torrellas. "InvisiSpec: making
speculative execution invisible in the cache hierarchy".
<<http://iacoma.cs.uiuc.edu/iacoma-papers/micro18.pdf>>

\[REF-2\] Alejandro Cabrera Aldaya, Billy Bob Brumley, Sohaib ul Hassan,
Cesar Pereida García, Nicola Tuveri. "Port Contention for Fun and
Profit". <<https://eprint.iacr.org/2018/1060.pdf>>

\[REF-3\] Mohammad Behnia, Prateek Sahu, Riccardo Paccagnella, Jiyong
Yu, Zirui Zhao, Xiang Zou, Thomas Unterluggauer, Josep Torrellas, Carlos
Rozas, Adam Morrison, Frank Mckeen, Fangfei Liu, Ron Gabor, Christopher
W. Fletcher, Abhishek Basak, Alaa Alameldeen. "Speculative Interference
Attacks: Breaking Invisible Speculation Schemes".
<<https://arxiv.org/abs/2007.11818>>

\[REF-4\] Ross Mcilroy, Jaroslav Sevcik, Tobias Tebbi, Ben L. Titzer,
Toon Verwaest. "Spectre is here to stay: An analysis of side-channels
and speculative execution". <<https://arxiv.org/pdf/1902.05178.pdf>>

\[REF-5\] Intel Corporation. "Managed Runtime Speculative Execution Side
Channel Mitigations".
<<https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/runtime-speculative-side-channel-mitigations.html>>

\[REF-6\] The Clang Team. "Control Flow Integrity".
<<https://clang.llvm.org/docs/ControlFlowIntegrity.html>>

\[REF-7\] Intel Corporation. "Retpoline: A Branch Target Injection
Mitigation".
<<https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/retpoline-branch-target-injection-mitigation.html>>

\[REF-8\] The kernel development community. "Speculation".
<<https://docs.kernel.org/6.6/staging/speculation.html>>

\[REF-9\] Chandler Carruth. "Speculative Load Hardening".
<<https://llvm.org/docs/SpeculativeLoadHardening.html>>

\[REF-10\] Alyssa Milburn, Ke Sun, Henrique Kawakami. "You Cannot Always
Win the Race: Analyzing the LFENCE/JMP Mitigation for Branch Target
Injection". <<https://arxiv.org/abs/2203.04277>>

\[REF-11\] Hany Ragab, Enrico Barberis, Herbert Bos, Cristiano
Giuffrida. "Rage Against the Machine Clear: A Systematic Analysis of
Machine Clears and Their Implications for Transient Execution Attacks".
<<https://www.usenix.org/system/files/sec21-ragab.pdf>>.

\[REF-12\] Oleksii Oleksenko, Marco Guarnieri, Boris Köpf, Mark
Silberstein. "Hide and Seek with Spectres: Efficient discovery of
speculative information leaks with random testing".
<<https://arxiv.org/pdf/2301.07642.pdf>>

\[REF-13\] Oleksii Oleksenko, Bohdan Trach, Mark Silberstein, Christof
Fetzer. "SpecFuzz: Bringing Spectre-type vulnerabilities to the
surface". <<https://www.usenix.org/system/files/sec20-oleksenko.pdf>>

\[REF-14\] Paul Kocher, Jann Horn, Anders Fogh, Daniel Genkin, Daniel
Gruss, Werner Haas, Mike Hamburg, Moritz Lipp, Stefan Mangard, Thomas
Prescher, Michael Schwarz, Yuval Yarom. "Spectre Attacks: Exploiting
Speculative Execution". <<https://spectreattack.com/spectre.pdf>>

### CWE-B: Exposure of Sensitive Information in Shared Microarchitectural Resource during Transient Execution

#### Description

A processor event may allow transient operations to access
architecturally restricted data (for example, in another address space)
in a shared microarchitectural resource (for example, a CPU cache),
potentially exposing the data over a covert channel.

#### Extended Description

Many commodity processors have Instruction Set Architecture (ISA)
features that protect software components from one another. These
features can include memory segmentation, virtual memory, privilege
rings, trusted execution environments, and virtual machines, among
others. For example, virtual memory provides each process with its own
address space, which prevents processes from accessing each other’s
private data. Many of these features can be used to form
hardware-enforced security boundaries between software components.

Many commodity processors also share microarchitectural resources that
cache (temporarily store) data, which may be confidential. These
resources may be shared across processor contexts, including across SMT
threads, privilege rings, or others.

When transient operations allow access to ISA-protected data in a shared
microarchitectural resource, this might violate users’ expectations of
the ISA feature that is bypassed. For example, if transient operations
can access a victim’s private data in a shared microarchitectural
resource, then the operations’ microarchitectural side effects may
correspond to the accessed data. If an attacker can trigger these
transient operations and observe their side effects through a covert
channel, then the attacker may be able to infer the victim’s private
data. Private data could include sensitive program data, OS/VMM data,
page table data (such as memory addresses), system configuration data
(see Demonstrative Example 3), or any other data that the attacker does
not have the required privileges to access.

#### Modes of Introduction

| Phase                   | Note                                                                                                                                                                                                                                                      |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Architecture and Design | This weakness can be introduced during hardware architecture and design if a data path allows architecturally restricted data to propagate to operations that execute before an older mis-prediction or processor event (such as an exception) is caught. |
| Implementation          | This weakness can be introduced during system software implementation if state-sanitizing operations are not invoked when switching from one context to another, according to the hardware vendor’s recommendations for mitigating the weakness.          |
| System Configuration    | This weakness can be introduced if the system has not been configured according to the hardware vendor’s recommendations for mitigating the weakness.                                                                                                     |

#### Potential Mitigations

##### Phase: Architecture and Design - Hardware

Hardware designers may choose to engineer the processor’s pipeline to
prevent architecturally restricted data from being used by operations
that can execute transiently.  
**Effectiveness: High**

Hardware designers may choose not to share microarchitectural resources
that can contain sensitive data, such as fill buffers and store
buffers.  
**Effectiveness: Moderate**  
**Note:** This can be highly effective at preventing this weakness from
being exposed across different SMT threads or different processor cores.
It is generally less practical to isolate these resources between
different contexts (for example, user and kernel) that may execute on
the same SMT thread or processor core.

Hardware designers may choose to sanitize specific microarchitectural
state (for example, store buffers) when the processor transitions to a
different context, such as whenever a system call is invoked.
Alternatively, the hardware may expose instruction(s) that allow
software to sanitize microarchitectural state according to the user or
system administrator’s threat model. These mitigation approaches are
similar to those that address
[CWE-226](https://cwe.mitre.org/data/definitions/226.html); however,
sanitizing microarchitectural state may not be the optimal or best way
to mitigate this weakness on every processor design.  
**Effectiveness: Moderate**  
**Note:** Sanitizing shared state on context transitions may not be
practical for all processors, especially when the amount of shared state
affected by the weakness is relatively large. Additionally, this
technique may not be practical unless there is a synchronous transition
between two processor contexts that would allow the affected resource to
be sanitized. For example, this technique alone may not suffice to
mitigate asynchronous access to a resource that is shared by two SMT
threads.

Software architects may design software to enforce strong isolation
between different contexts. For example, kernel page table isolation
(KPTI) mitigates the Meltdown vulnerability \[REF-4\] by separating
user-mode page tables from kernel-mode page tables, which prevents
user-mode processes from using Meltdown to transiently access kernel
memory \[REF-1\].  
**Effectiveness: Limited**  
**Note:** Isolating different contexts across a process boundary (or
another kind of architectural boundary) may only be effective for some
weaknesses.

##### Phase: Build and Compilation

If the weakness is exposed by a single instruction (or a small set of
instructions), then the compiler (or JIT, etc.) can be configured to
prevent the affected instruction(s) from being generated, and instead
generate an alternate sequence of instructions that is not affected by
the weakness.  
**Effectiveness: Limited**  
**Note:** This technique may only be fully effective if it is applied to
all software that runs on the system. Also, relatively few observed
examples of this weakness have exposed data through only a single
instruction.

##### Phase: Implementation

System software can mitigate this weakness by invoking state-sanitizing
operations when switching from one context to another, according to the
hardware vendor’s recommendations.  
**Effectiveness: Limited**  
**Note:** This technique may not be able to mitigate weaknesses that
arise from resource sharing across SMT threads.

##### Phase: System Configuration

Some systems may allow the user to disable (for example, in the BIOS)
sharing of the affected resource.  
**Effectiveness: Limited**  
**Note:** Disabling resource sharing (for example, by disabling SMT)
may result in significant performance overhead.

Some systems may allow the user to disable (for example, in the BIOS)
microarchitectural features that allow transient access to
architecturally restricted data.  
**Effectiveness: Limited**  
**Note:** Disabling microarchitectural features such as predictors may
result in significant performance overhead.

##### Phase: Patching and Maintenance

The hardware vendor may provide a patch to sanitize the affected shared
microarchitectural state when the processor transitions to a different
context.  
**Effectiveness: Moderate**  
**Note:** This technique may not be able to mitigate weaknesses that arise
from resource sharing across SMT threads.

The hardware vendor may provide a patch to prevent transient operations
from accessing architecturally restricted data in shared
microarchitectural resources.  
**Effectiveness: Limited**  
**Note:** This kind of patch may not be feasible or implementable for all
processors or all weaknesses.

#### Detection Methods

##### Manual Analysis

This weakness can be detected in hardware by manually inspecting
processor specifications. Features that exhibit this weakness may
include microarchitectural predictors, access control checks that occur
out-of-order, or any other features that can allow operations to execute
without committing to architectural state. Academic researchers have
demonstrated that new hardware weaknesses can be discovered by examining
publicly available patent filings, for example \[REF-2\] and \[REF-3\].

##### Automated Analysis - Pre-discovery

This weakness can be detected in hardware by employing static or dynamic
taint analysis methods \[REF-4\]. These methods can label data in one
context (for example, kernel data) and perform information flow analysis
(or a simulation, etc.) to determine whether tainted data can appear in
another context (for example, user mode). Alternatively, stale or
invalid data in shared microarchitectural resources can be marked as
tainted, and the taint analysis framework can identify when transient
operations encounter tainted data.

##### Automated Analysis - Post-discovery

Software vendors can release tools that detect presence of known
weaknesses on a processor. For example, some of these tools can attempt
to transiently execute a vulnerable code sequence and detect whether
code successfully leaks data in a manner consistent with the weakness
under test. Alternatively, some hardware vendors provide enumeration for
the presence of a weakness (or lack of a weakness). These enumeration
bits can be checked and reported by system software. For example, Linux
supports these checks for many commodity processors:

    $ cat /proc/cpuinfo | grep bugs | head -n 1
    bugs            : cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs taa itlb_multihit srbds mmio_stale_data retbleed

#### Common Consequences

| Scope           | Impact                                               | Likelihood |
| --------------- | ---------------------------------------------------- | ---------- |
| Confidentiality | Technical Impact: Read Memory, Read System Registers | Medium     |

#### Applicable Platforms

##### Languages

Class: Not Language-Specific *(Undetermined Prevalence)*

##### Operating Systems

Class: Not OS-Specific *(Undetermined Prevalence)*

##### Architectures

Class: Not Architecture-Specific *(Undetermined Prevalence)*

##### Technologies

Class: Not Technology-Specific *(Undetermined Prevalence)*

#### Demonstrative Examples

##### Example 1

Some processors may perform access control checks in parallel with
memory read/write operations. For example, when a user-mode program
attempts to read data from memory, the processor may also need to check
whether the memory address is mapped into user space or kernel space. If
the processor performs the access concurrently with the check, then the
access may be able to transiently read kernel data before the check
completes. This race condition is demonstrated in the following code:

    Example Language: x86-64 Assembly Language
    1 ; rcx = kernel address, rbx = probe array
    2 xor rax, rax                # set rax to 0
    3 retry:
    4 mov al, byte [rcx]          # attempt to read kernel memory
    5 shl rax, 0xc                # multiply result by page size (4KB)
    6 jz retry                    # if the result is zero, try again
    7 mov rbx, qword [rbx + rax]  # transmit result over a cache covert channel

Vulnerable processors may return kernel data from a shared
microarchitectural resource in line `4`, for example, from the
processor’s L1 data cache. Since this vulnerability involves a race
condition, the `mov` in line `4` may not always return kernel data (that
is, whenever the check "wins" the race), in which case this
demonstration code re-attempts the access in line `6`. The accessed data
is multiplied by 4KB, a common page size, to make it easier to observe
via a cache covert channel after the transmission in line `7`. The use
of cache covert channels to observe the side effects of transient
execution has been described in \[REF-5\].

Code snippet is from \[REF-5\], with additional annotations.

##### Example 2

Many commodity processors share microarchitectural fill buffers between
sibling hardware threads on simultaneous multithreaded (SMT) processors.
Fill buffers can serve as temporary storage for data that passes to and
from the processor’s caches. Microarchitectural Fill Buffer Data
Sampling (MFBDS) is a vulnerability that can allow a hardware thread to
access its sibling’s private data in a shared fill buffer. The access
may be prohibited by the processor’s ISA, but MFBDS can allow the access
to occur during transient execution, in particular during a faulting
operation or an operation that triggers a microcode assist.

More information on MFBDS can be found in \[REF-2\] and \[REF-6\].

##### Example 3

Some processors may allow access to system registers (for example,
system coprocessor registers or model-specific registers) during
transient execution. This scenario is depicted in the code snippet
below. Under ordinary operating circumstances, code in exception level 0
(EL0) is not permitted to access registers that are restricted to EL1,
such as `TTBR0_EL1`. However, on some processors an earlier
mis-prediction can cause the `MRS` instruction to transiently read the
value in an EL1 register. In this example, a conditional branch (line 2)
can be mis-predicted as "not taken" while waiting for a slow load (line
1). This allows `MRS` (line 3) to transiently read the value in the
`TTBR0_EL1` register. The subsequent memory access (line 6) can allow
the restricted register’s value to become observable, for example, over
a cache covert channel.

    Example Language: Arm Assembly Language
    1 LDR X1, [X2] ; arranged to miss in the cache
    2 CBZ X1, over ; This will be taken 
    3 MRS X3, TTBR0_EL1; 
    4 LSL X3, X3, #imm 
    5 AND X3, X3, #0xFC0
    6 LDR X5, [X6,X3] ; X6 is an EL0 base address
    7 over

Code snippet is from \[REF-7\]. See also \[REF-8\].

#### Observed Examples

| Reference                                                       | Description                                                                                                                                             |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [CVE-2017-5715](https://www.cve.org/CVERecord?id=CVE-2017-5715) | A fault may allow transient user-mode operations to access kernel data cached in the L1D, potentially exposing the data over a covert channel.          |
| [CVE-2018-3615](https://www.cve.org/CVERecord?id=CVE-2018-3615) | A fault may allow transient non-enclave operations to access SGX enclave data cached in the L1D, potentially exposing the data over a covert channel.   |
| [CVE-2019-1135](https://www.cve.org/CVERecord?id=CVE-2019-1135) | A TSX Asynchronous Abort may allow transient operations to access architecturally restricted data, potentially exposing the data over a covert channel. |

#### Relationships

  - Child of CWE-A

#### Notes

##### Relationship

CWE-D and CWE-B both involve shared microarchitectural features. The
difference between these two is that CWE-B covers shared state that is
used for program data, whereas CWE-D covers shared microarchitectural
predictor state.

#### References

\[REF-1\] The kernel development community. "Page Table Isolation
(PTI)". <<https://kernel.org/doc/html/next/x86/pti.html>>

\[REF-2\] Stephan van Schaik, Alyssa Milburn, Sebastian Österlund,
Pietro Frigo, Giorgi Maisuradze, Kaveh Razavi, Herbert Bos, Cristiano
Giuffrida. "RIDL: Rogue In-Flight Data Load".
<<https://mdsattacks.com/files/ridl.pdf>>

\[REF-3\] Daniel Moghimi. "Downfall: Exploiting Speculative Data
Gathering".
<<https://www.usenix.org/system/files/usenixsecurity23-moghimi.pdf>>

\[REF-4\] Neta Bar Kama, Roope Kaivola. "Hardware Security Leak
Detection by Symbolic Simulation".
<<https://ieeexplore.ieee.org/document/9617727>>

\[REF-5\] Moritz Lipp, Michael Schwarz, Daniel Gruss, Thomas Prescher,
Werner Haas, Stefan Mangard, Paul Kocher, Daniel Genkin, Yuval Yarom,
Mike Hamburg. "Meltdown: Reading Kernel Memory from User Space".
<<https://meltdownattack.com/meltdown.pdf>>

\[REF-6\] Intel Corporation. "Microarchitectural Data Sampling".
<<https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/intel-analysis-microarchitectural-data-sampling.html>>

\[REF-7\] Arm. "Whitepaper Cache Speculation Side-channels".
<<https://armkeil.blob.core.windows.net/developer/Files/pdf/Cache\_Speculation\_Side-channels\_03May18.pdf>>

\[REF-8\] Intel Corporation. "Rogue System Register Read / CVE-2018-3640
/ INTEL-SA-00115".
<<https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/advisory-guidance/rogue-system-register-read.html>>

### CWE-C: Exposure of Sensitive Information caused by Incorrect Data Forwarding during Transient Execution

#### Description

A processor event or prediction may allow incorrect or stale data to be
forwarded to transient operations, potentially exposing data over a
covert channel.

#### Extended Description

Software may use a variety of techniques to preserve the confidentiality
of private data that is accessible within the current processor context.
For example, the memory safety and type safety properties of some
high-level programming languages help to prevent software written in
those languages from exposing private data. As a second example,
software sandboxes may co-locate multiple users’ software within a
single process. The processor’s Instruction Set Architecture (ISA) may
permit one user’s software to access another user’s data (because the
software shares the same address space), but the sandbox prevents these
accesses by using software techniques such as bounds checking.

If incorrect or stale data can be forwarded (for example, from a cache)
to transient operations, then the operations’ microarchitectural side
effects may correspond to the data. If an attacker can trigger these
transient operations and observe their side effects through a covert
channel, then the attacker may be able to infer the data. For example,
an attacker process may induce transient execution in a victim process
that causes the victim to inadvertently access and then expose its
private data via a covert channel. In the software sandbox example, an
attacker sandbox may induce transient execution in its own code,
allowing it to transiently access and expose data in a victim sandbox
that shares the same address space.

Consequently, weaknesses that arise from incorrect/stale data forwarding
might violate users’ expectations of software-based memory safety and
isolation techniques. If the data forwarding behavior is not properly
documented by the hardware vendor, this might violate the software
vendor’s expectation of how the hardware should behave.

#### Modes of Introduction

| Phase                   | Note                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Architecture and Design | This weakness can be introduced by data speculation techniques, or when the processor pipeline is designed to check exception conditions concurrently with other operations. This weakness can also persist after a CWE-B weakness has been mitigated. For example, suppose that a processor can forward stale data from a shared microarchitectural buffer to dependent transient operations, and furthermore suppose that the processor has been patched to flush the buffer on context switches. This mitigates the CWE-B weakness, but the stale-data forwarding behavior may persist as a CWE-C weakness unless this behavior is also patched. |

#### Potential Mitigations

##### Phase: Requirements

Processor designers may expose instructions or other architectural
features that allow software to mitigate the effects of transient
execution, but without disabling predictors. These features may also
help to limit opportunities for data exposure.  
**Effectiveness: Moderate**  
**Note:** Instructions or features that constrain transient execution or
suppress its side effects may impact performance.

Processor designers may expose registers (for example, control registers
or model-specific registers) that allow privileged and/or user software
to disable specific predictors or other hardware features that can cause
confidential data to be exposed during transient execution.  
**Effectiveness: Limited**  
**Note:** Disabling specific predictors or other hardware features may
result in significant performance overhead.

##### Phase: Build and Compilation

Isolate sandboxes or managed runtimes in separate address spaces
(separate processes).  
**Effectiveness: High**  
**Note:** Process isolation is also an effective strategy to mitigate many
other kinds of weaknesses.

Include serialization instructions (for example, LFENCE) that prevent
processor events or mis-predictions prior to the serialization
instruction from causing transient execution after the serialization
instruction. For some weaknesses, a serialization instruction can also
prevent a processor event or a mis-prediction from occurring after the
serialization instruction (for example,
[CVE-2018-3639](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3639)
can allow a processor to predict that a load will not depend on an older
store; a serialization instruction between the store and the load may
allow the store to update memory and prevent the mis-prediction from
happening at all).  
**Effectiveness: Moderate**  
**Note:** When used to comprehensively mitigate a transient execution
weakness, serialization instructions can introduce significant
performance overhead.

Use software techniques that can mitigate the consequences of transient
execution. For example, address masking can be used in some
circumstances to prevent out-of-bounds transient reads.  
**Effectiveness: Limited**  
**Note:** Address masking and related software mitigation techniques have
been used to harden specific code sequences that could potentially be
exploited via transient execution. For example, the Linux kernel makes
limited use of this technique to mitigate bounds-check bypass \[REF-1\].

If the weakness is exposed by a single instruction (or a small set of
instructions), then the compiler (or JIT, etc.) can be configured to
prevent the affected instruction(s) from being generated, and instead
generate an alternate sequence of instructions that is not affected by
the weakness.  
**Effectiveness: Limited**  
**Note:** This technique is only effective for software that is compiled
with this mitigation.

##### Phase: Documentation

If a hardware feature can allow incorrect or stale data to be forwarded
to transient operations, the hardware designer may opt to disclose this
behavior in architecture documentation. This documentation can inform
users about potential consequences and effective mitigations.  
**Effectiveness: High**

#### Detection Methods

##### Automated Static Analysis

A variety of automated static analysis tools can identify potentially
exploitable code sequences in software. These tools may perform the
analysis on source code, on binary code, or on an intermediate code
representation (for example, during compilation).

##### Manual Analysis

This weakness can be detected in hardware by manually inspecting
processor specifications. Features that exhibit this weakness may
include microarchitectural predictors, access control checks that occur
out-of-order, or any other features that can allow operations to execute
without committing to architectural state.

##### Automated Analysis

Software vendors can release tools that detect presence of known
weaknesses on a processor. For example, some of these tools can attempt
to transiently execute a vulnerable code sequence and detect whether
code successfully leaks data in a manner consistent with the weakness
under test. Alternatively, some hardware vendors provide enumeration for
the presence of a weakness (or lack of a weakness). These enumeration
bits can be checked and reported by system software. For example, Linux
supports these checks for many commodity processors:

    $ cat /proc/cpuinfo | grep bugs | head -n 1
    bugs            : cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs taa itlb_multihit srbds mmio_stale_data retbleed

#### Common Consequences

| Scope           | Impact                        | Likelihood |
| --------------- | ----------------------------- | ---------- |
| Confidentiality | Technical Impact: Read Memory | Medium     |

#### Applicable Platforms

##### Languages

Class: Not Language-Specific *(Undetermined Prevalence)*

##### Operating Systems

Class: Not OS-Specific *(Undetermined Prevalence)*

##### Architectures

Class: Not Architecture-Specific *(Undetermined Prevalence)*

##### Technologies

Class: Not Technology-Specific *(Undetermined Prevalence)*

#### Demonstrative Examples

##### Example 1

Faulting loads in a victim domain may trigger incorrect transient
forwarding, which leaves secret-dependent traces in the
microarchitectural state. Consider this code sequence example from
\[REF-2\]:

    Example Language: C
    void call_victim(size_t untrusted_arg) {
      *arg_copy = untrusted_arg;
      array[**trusted_ptr * 4096];
    }

A processor with this weakness will store the value of `untrusted_arg`
(which may be provided by an attacker) to the stack, which is trusted
memory. Additionally, this store operation will save this value in some
microarchitectural buffer, for example, the store buffer.

In this code sequence, `trusted_ptr` is dereferenced while the attacker
forces a page fault. The faulting load causes the processor to
mis-speculate by forwarding `untrusted_arg` as the (transient) load
result. The processor then uses `untrusted_arg` for the pointer
dereference. After the fault has been handled and the load has been
re-issued with the correct argument, secret-dependent information stored
at the address of `trusted_ptr` remains in microarchitectural state and
can be extracted by an attacker using a vulnerable code sequence.

##### Example 2

Some processors try to predict when a store will forward data to a
subsequent load, even when the address of the store or the load is not
yet known. For example, on Intel processors this feature is called a
Fast Store Forwarding Predictor (\[REF-3\]), and on AMD processors the
feature is called Predictive Store Forwarding (\[REF-4\]). A
misprediction can cause incorrect or stale data to be forwarded from a
store to a load, as illustrated in the following code snippet from
\[REF-4\]:

    Example Language: C
    1. void fn(int idx) {
    2.   unsigned char v;
    3.   idx_array[0] = 4096;
    4.   v = array[idx_array[idx] * (idx)];
    5. }

In this example, assume that the parameter `idx` can only be `0` or `1`,
and assume that `idx_array` initially contains all `0`s. Observe that
the assignment to `v` in line 4 will be `array[0]`, regardless of
whether `idx=0` or `idx=1`. Now suppose that an attacker repeatedly
invokes `fn` with `idx=0` to train the store forwarding predictor to
predict that the store in line 3 will forward the data `4096` to the
load `idx_array[idx]` in line 4. Then, when the attacker invokes `fn`
with `idx=1` the predictor may cause `idx_array[idx]` to transiently
produce the incorrect value `4096`, and therefore `v` will transiently
be assigned the value `array[4096]`, which otherwise would not have been
accessible in line 4.

Although this toy example is benign (it doesn’t transmit `array[4096]`
over a covert channel), an attacker may be able to use similar
techniques to craft and train malicious code sequences to, for example,
read data beyond a software sandbox boundary.

#### Observed Examples

| Reference                                                       | Description                                                                                                                                                                                                                                                   |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [CVE-2020-0551](https://www.cve.org/CVERecord?id=CVE-2020-0551) | A fault, microcode assist, or abort may allow transient load operations to forward malicious stale data to dependent operations executed by a victim, causing the victim to unintentionally access and potentially expose its own data over a covert channel. |
| [CVE-2020-8698](https://www.cve.org/CVERecord?id=CVE-2020-8698) | A fast store forwarding predictor may allow store operations to forward incorrect data to transient load operations, potentially exposing data over a covert channel.                                                                                         |

#### Relationships

  - Child of CWE-A

#### Notes

##### Relationship

If a weakness involves incorrect data forwarding and also allows
transient access to architecturally restricted data, then the weakness
is an instance of CWE-B. CWE-C includes weaknesses that forward
incorrect data that is not architecturally restricted.

#### References

\[REF-1\] The kernel development community. "Speculation".
<<https://docs.kernel.org/6.6/staging/speculation.html>>

\[REF-1\] Jo Van Bulck, Daniel Moghimi, Michael Schwarz, Moritz Lipp,
Marina Minkin, Daniel Genkin, Yuval Yarom, Berk Sunar, Daniel Gruss, and
Frank Piessens. "LVI: Hijacking Transient Execution through
Microarchitectural Load Value Injection". 2020-01-09.
<<https://lviattack.eu/lvi.pdf>>.

\[REF-2\] Intel Corporation. "Fast Store Forwarding Predictor".
<<https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/fast-store-forwarding-predictor.html>>

\[REF-3\] AMD. "Security Analysis Of AMD Predictive Store Forwarding".
<<https://www.amd.com/system/files/documents/security-analysis-predictive-store-forwarding.pdf>>

### CWE-D: Exposure of Sensitive Information caused by Shared Microarchitectural Predictor State that influences Transient Execution

#### Description

Shared microarchitectural predictor state may allow code to influence
transient execution across a hardware boundary, potentially exposing
data that is accessible beyond the boundary over a covert channel.

#### Extended Description

Many commodity processors have Instruction Set Architecture (ISA)
features that protect software components from one another. These
features can include memory segmentation, virtual memory, privilege
rings, trusted execution environments, and virtual machines, among
others. For example, virtual memory provides each process with its own
address space, which prevents processes from accessing each other’s
private data. Many of these features can be used to form
hardware-enforced security boundaries between software components.

When separate software components (for example, two processes) share
microarchitectural predictor state across a hardware boundary, code in
one component may be able to influence microarchitectural predictor
behavior in another component. If the predictor can cause transient
execution, the shared predictor state may allow an attacker to influence
transient execution in a victim, and in a manner that could allow the
attacker to infer private data from the victim.

Predictor state may be shared when the processor transitions from one
component to another (for example, when a process makes a system call to
enter the kernel). Many commodity processors have features which prevent
microarchitectural predictions that occur before a boundary from
influencing predictions that occur after the boundary.

Predictor state may also be shared between hardware threads, for
example, sibling hardware threads on a processor that supports
simultaneous multithreading (SMT). This sharing may be benign if the
hardware threads are simultaneously executing in the same software
component, or it could expose a weakness if one sibling is a malicious
software component and the other sibling is a victim software component.
Processors that share microarchitectural predictors between hardware
threads may have features which prevent microarchitectural predictions
that occur on one hardware thread from influencing predictions that
occur on another hardware thread.

Features that restrict predictor state sharing across transitions or
between hardware threads may be always-on, on by default, or may require
opt-in from software.

#### Modes of Introduction

| Phase                   | Note                                                                                                                                                                                                                                                                                                                                    |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Architecture and Design | This weakness can be introduced during hardware architecture and design if predictor state is not properly isolated between modes (for example, user mode and kernel mode), if predictor state is not isolated between hardware threads, or if it is not isolated between other kinds of execution contexts supported by the processor. |
| Implementation          | This weakness can be introduced during system software implementation if predictor-state-sanitizing operations (for example, the indirect branch prediction barrier on Intel x86) are not invoked when switching from one context to another.                                                                                           |
| System Configuration    | This weakness can be introduced if the system has not been configured according to the hardware vendor’s recommendations for mitigating the weakness.                                                                                                                                                                                   |

#### Potential Mitigations

##### Phase: Architecture and Design

Hardware designers may choose to use microarchitectural bits to tag
predictor entries. For example, each predictor entry may be tagged with
a kernel-mode bit which, when set, indicates that the predictor entry
was created in kernel mode. The processor can use this bit to enforce
that predictions in the current mode must have been trained in the
current mode. This can prevent malicious cross-mode training, such as
when user-mode software attempts to create predictor entries that
influence transient execution in the kernel. Predictor entry tags can
also be used to associate each predictor entry with the SMT thread that
created it, and thus the processor can enforce that each predictor entry
can only be used by the SMT thread that created it. This can prevent an
SMT thread from using predictor entries crafted by a malicious sibling
SMT thread.  
**Effectiveness: Moderate**  
**Note:** Tagging can be highly effective for predictor state that is
comprised of discrete elements, such as an array of recently visited
branch targets. Predictor state can also have different representations
that are not conducive to tagging. For example, some processors keep a
compressed digest of branch history which does not contain discrete
elements that can be individually tagged.

Hardware designers may choose to sanitize microarchitectural predictor
state (for example, branch prediction history) when the processor
transitions to a different context, for example, whenever a system call
is invoked. Alternatively, the hardware may expose instruction(s) that
allow software to sanitize predictor state according to the user’s
threat model. For example, this can allow operating system software to
sanitize predictor state when performing a context switch from one
process to another.  
**Effectiveness: Moderate**  
**Note:** This technique may not be able to mitigate weaknesses that arise
from predictor state that is shared across SMT threads. Sanitizing
predictor state on context switches may also negatively impact
performance, either by removing predictor entries that could be reused
when returning to the previous context, or by slowing down the context
switch itself.

##### Phase: Implementation

System software can mitigate this weakness by invoking
predictor-state-sanitizing operations (for example, the indirect branch
prediction barrier on Intel x86) when switching from one context to
another, according to the hardware vendor’s recommendations.  
**Effectiveness: Moderate**  
**Note:** This technique may not be able to mitigate weaknesses that
arise from predictor state shared across SMT threads. Sanitizing
predictor state may also negatively impact performance in some
circumstances.

##### Phase: Build and Compilation

If the weakness is exposed by a single instruction (or a small set of
instructions), then the compiler (or JIT, etc.) can be configured to
prevent the affected instruction(s) from being generated. One prominent
example of this mitigation is retpoline (\[REF-1\]).  
**Effectiveness: Limited**  
**Note:** This technique is only effective for software that is compiled
with this mitigation. Additionally, an alternate instruction sequence
may mitigate the weakness on some processors but not others, even when
the processors share the same ISA. For example, retpoline has been
documented as effective on some x86 processors, but not fully effective
on other x86 processors.

##### Phase: System Configuration

Some systems may allow the user to disable predictor sharing. For
example, this could be a BIOS configuration, or a model-specific
register (MSR) that can be configured by the operating system or virtual
machine monitor.  
**Effectiveness: Moderate**  
**Note:** Disabling predictor sharing can negatively impact performance
for some workloads that benefit from shared predictor state.

##### Phase: Patching and Maintenance

The hardware vendor may provide a patch to, for example, sanitize
predictor state when the processor transitions to a different context,
or to prevent predictor entries from being shared across SMT threads. A
patch may also introduce new ISA that allows software to toggle a
mitigation.  
**Effectiveness: Moderate**  
**Note:** This mitigation may only be fully effective if the patch
prevents predictor sharing across all contexts that are affected by the
weakness. Additionally, sanitizing predictor state and/or preventing
shared predictor state can negatively impact performance in some
circumstances.

##### Phase: Documentation

If a hardware feature can allow microarchitectural predictor state to be
shared between contexts, SMT threads, or other architecturally defined
boundaries, the hardware designer may opt to disclose this behavior in
architecture documentation. This documentation can inform users about
potential consequences and effective mitigations.  
**Effectiveness: High**

#### Detection Methods

##### Manual Analysis

This weakness can be detected in hardware by manually inspecting
processor specifications. Features that exhibit this weakness may have
microarchitectural predictor state that is shared between hardware
threads, execution contexts (for example, user and kernel), or other
components that may host mutually distrusting software (or firmware,
etc.).

##### Automated Analysis

Software vendors can release tools that detect presence of known
weaknesses on a processor. For example, some of these tools can attempt
to transiently execute a vulnerable code sequence and detect whether
code successfully leaks data in a manner consistent with the weakness
under test. Alternatively, some hardware vendors provide enumeration for
the presence of a weakness (or lack of a weakness). These enumeration
bits can be checked and reported by system software. For example, Linux
supports these checks for many commodity processors:

    $ cat /proc/cpuinfo | grep bugs | head -n 1
    bugs            : cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs taa itlb_multihit srbds mmio_stale_data retbleed

#### Common Consequences

| Scope           | Impact                        | Likelihood |
| --------------- | ----------------------------- | ---------- |
| Confidentiality | Technical Impact: Read Memory | Medium     |

#### Applicable Platforms

##### Languages

Class: Not Language-Specific *(Undetermined Prevalence)*

##### Operating Systems

Class: Not OS-Specific *(Undetermined Prevalence)*

##### Architectures

Class: Not Architecture-Specific *(Undetermined Prevalence)*

##### Technologies

Class: Not Technology-Specific *(Undetermined Prevalence)*

#### Demonstrative Examples

##### Example 1

Branch Target Injection (BTI) is a vulnerability that can allow an SMT
hardware thread to maliciously train the indirect branch predictor state
that is shared with its sibling hardware thread. A cross-thread BTI
attack requires the attacker to find a vulnerable code sequence within
the victim software. For example, the authors of \[REF-2\] identified
the following code sequence in the Windows library `ntdll.dll`:

    Example Language: x86-64 Assembly Language
    example_code_sequence:
      adc edi,dword ptr [ebx+edx+13BE13BDh]
      adc dl,byte ptr [edi]

To successfully exploit this code sequence to disclose the victim’s
private data, the attacker must also be able to find an indirect branch
site within the victim, where the attacker controls the values in `edi`
and `ebx`, and the attacker knows the value in `edx`, such as:

    Example Language: x86-64 Assembly Language
    indirect_branch_site:
      jmp dword ptr [rsi]   # at this point attacker knows edx, controls edi and ebx

A proof-of-concept cross-thread BTI attack might proceed as follows:

1.  The attacker thread and victim thread must be co-scheduled on the
    same physical processor core.

2.  The attacker thread must train the shared branch predictor so that
    when the victim thread reaches `indirect_branch_site`, the `jmp`
    instruction will be predicted to target `example_code_sequence`
    instead of the correct architectural target. The training procedure
    may vary by processor, and the attacker may need to reverse-engineer
    the branch predictor to identify a suitable training algorithm.

3.  This step assumes that the attacker can control some values in the
    victim program, specifically the values in `edi` and `ebx` at
    `indirect_branch_site`. When the victim reaches
    `indirect_branch_site` the processor will (mis)predict
    `example_code_sequence` as the target and (transiently) execute the
    `adc` instructions. If the attacker chooses `ebx` so that `ebx = m
    - 0x13BE13BD - edx`, then the first `adc` will load 32 bits from
    address `m` in the victim’s address space and add `*m` (the data
    loaded from `m`) to the attacker-controlled base address in `edi`.
    The second `adc` instruction accesses a location in memory whose
    address corresponds to `*m`.

4.  The adversary uses a covert channel analysis technique such as
    Flush+Reload (\[REF-3\]) to infer the value of the victim’s private
    data `*m`.

##### Example 2

BTI can also allow software in one execution context to maliciously
train branch predictor entries that can be used in another context. For
example, on some processors user-mode software may be able to train
predictor entries that can also be used after transitioning into kernel
mode, such as after invoking a system call. This vulnerability does not
necessarily require SMT and may instead be performed in synchronous
steps, though it does require the attacker to find an exploitable code
sequence in the victim’s code, for example, in the kernel.

#### Observed Examples

| Reference                                                         | Description                                                                                                                                                                                                                                     |
| ----------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [CVE-2017-5754](https://www.cve.org/CVERecord?id=CVE-2017-5754)   | Shared microarchitectural indirect branch predictor state may allow code to influence transient execution across a process, VM, or privilege boundary, potentially exposing data that is accessible beyond the boundary.                        |
| [CVE-2022-0001](https://www.cve.org/CVERecord?id=CVE-2022-0001)   | Shared branch history state may allow user-mode code to influence transient execution in the kernel, potentially exposing kernel data over a covert channel.                                                                                    |
| [CVE-2021-33149](https://www.cve.org/CVERecord?id=CVE-2021-33149) | Shared return stack buffer state may allow code that executes before a prediction barrier to influence transient execution after the prediction barrier, potentially exposing data that is accessible beyond the barrier over a covert channel. |

#### Relationships

  - Child of CWE-A

#### Notes

##### Relationship

CWE-D and CWE-B both involve shared microarchitectural features. The
difference between these two is that CWE-B covers shared state that is
used for program data, whereas CWE-D covers shared microarchitectural
predictor state.

#### References

\[REF-1\] Intel Corporation. "Retpoline: A Branch Target Injection
Mitigation".
<<https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/retpoline-branch-target-injection-mitigation.html>>

\[REF-2\] Paul Kocher, Jann Horn, Anders Fogh, Daniel Genkin, Daniel
Gruss, Werner Haas, Mike Hamburg, Moritz Lipp, Stefan Mangard, Thomas
Prescher, Michael Schwarz, Yuval Yarom. "Spectre Attacks: Exploiting
Speculative Execution". <<https://spectreattack.com/spectre.pdf>>.

\[REF-3\] Yuval Yarom, Katrina Falkner. "Flush+Reload: A High
Resolution, Low Noise, L3 Cache Side-Channel Attack".
<<https://www.usenix.org/system/files/conference/usenixsecurity14/sec14-paper-yarom.pdf>>

### CWE-E: Speculative Oracle (full title TBD)

#### Description

TBD

#### Extended Description

TBD

#### Modes of Introduction

| Phase | Note |
| ----- | ---- |
|       |      |
|       |      |

#### Potential Mitigations

#### Common Consequences

| Scope | Impact | Likelihood |
| ----- | ------ | ---------- |
|       |        |            |

#### Applicable Platforms

##### Languages

Class: Not Language-Specific *(Undetermined Prevalence)*

##### Operating Systems

Class: Not OS-Specific *(Undetermined Prevalence)*

##### Architectures

Class: Not Architecture-Specific *(Undetermined Prevalence)*

##### Technologies

Class: Not Technology-Specific *(Undetermined Prevalence)*

#### Demonstrative Examples

TBD

#### Observed Examples

| Reference | Description |
| --------- | ----------- |
|           |             |

#### Relationships

  - Child of CWE-A

#### References

TBD

## Author’s Notes

  - When writing these descriptions, I have tried as much as possible to
    avoid introducing new terms, or terms that are specific to Intel’s
    literature/documentation.
    
      - Intel often uses "malicious adversary," but here I have used
        "attacker" to align with the [CWE
        glossary](https://cwe.mitre.org/documents/glossary/).
    
      - "Transient," "transient execution," "transient operations," etc.
        do not exist in the CWE glossary but have been used in other
        CWEs. I had initially drafted these descriptions without using
        the word "transient," but this often led to unappealing
        verbosity—I had to spell out "operations that execute but do not
        commit to architectural state" many times. Perhaps MITRE should
        consider adding "transient" to its CWE glossary.
    
      - I make liberal use of the term "processor event," which is
        intended to convey "something that happens while the processor
        is executing operations." This could be anything from a fault to
        a snoop assist.

  - I have tried my best to adhere to the [submission
    guidelines](https://cwe.mitre.org/community/submissions/guidelines.html#introduction)
    provided by MITRE (see Appendix):
    
      - **Name:** Each CWE name is intended to focus on the weakness,
        not a specific attack. Each name hints at the weakness category
        ("Transient" or "Transient Execution") and the affected
        technology ("Processor" or "Microarchitecture"). CWE-C applies
        to a specific kind of resource, "shared microarchitectural
        predictor state," which is included in the name.
    
      - **Summary:** Each summary is intended to describe the weakness
        itself in a single sentence. Following MITRE’s guidelines, I
        have avoided focusing on any particular attack, the absence of a
        mitigation, and the potential impact.
    
      - **Extended Description:** Following MITRE’s guidelines, I have
        used the extended descriptions to highlight potential impacts
        for developers, and to generalize the mitigation strategies that
        have been adopted throughout the industry.

  - We removed a CWE that applied exclusively to predictor-based
    transient execution not involving shared predictor state. We believe
    that CWE-A suffices to cover these cases.

  - Some of that CWE’s extended description has been updated and merged
    into CWE-A.

  - There is a placeholder CWE-E that will cover "speculation oracle"
    weaknesses such as PACMAN.

  - The Observed Examples use the proposed CWE descriptions, instead of
    the original CVE descriptions.

  - Demonstrated Example 1 in CWE-A is nearly the same as an older
    demonstrated example in CWE-1303.

  - Demonstrated Example 1 in CWE-C is nearly the same as an older
    demonstrated example in CWE-1342.

  - CWE-B and CWE-D are both related to CWE-1189. Should this
    relationship be conveyed, and if so, how?

  - The term "confused deputy" would be useful to describe some exploits
    that could fall within CWE-A and CWE-C, but this term does not
    appear in the CWE glossary. This term could be useful for other CWEs
    as well.

  - The novel term "hardware domain" was removed from this proposal.
    This term is difficult to define and, once defined, becomes too
    rigid. Instead, this proposal contrasts "data protected by hardware"
    with "data protected by software." This revised language is intended
    to provide hardware designers with flexibility to specify what their
    hardware is intended to protect.

<!-- end list -->

  - The "effectiveness" ratings for mitigations are determined by the
    CWE schema:
    
      - "The EffectivenessEnumeration simple type defines the different
        values related to how effective a mitigation may be in
        preventing the weakness. A value of "High" means the mitigation
        is frequently successful in eliminating the weakness entirely. A
        value of "Moderate" means the mitigation will prevent the
        weakness in multiple forms, but it does not have complete
        coverage of the weakness. A value of "Limited" means the
        mitigation may be useful in limited circumstances, or it is only
        applicable to a subset of potential errors of this weakness
        type. A value of "Incidental" means the mitigation is generally
        not effective and will only provide protection by chance, rather
        than in a reliable manner. A value of "Defense in Depth" means
        the mitigation may not necessarily prevent the weakness, but it
        may help to minimize the potential impact of an attacker
        exploiting the weakness. A value of "Discouraged Common
        Practice" is used to indicate mitigations that are commonly
        attempted but known to be ineffective or highly risky."

## Applying These New CWEs to A Variety of Transient Execution CVEs

The following is a partial survey of existing CVEs that pertain to
transient execution. Each entry in the table compares the current CVE
description against a hypothetical CVE description that derives from the
draft CWE language introduced earlier in this document. Note that many
CVEs issued prior to 2021 did not use CWE descriptions, indicated by
"\[No CWE\]."

| CVE                                                                                | Current Description                                                                                                                                                                                                                                                                                  | New Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ---------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CVE-2017-5715 (Rogue Data Cache Load, RDCL, Meltdown, Variant 3)                   | \[No CWE\] Systems with microprocessors utilizing speculative execution and indirect branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis of the data cache.                                                         | \[CWE-B\] A fault may allow transient user-mode operations to access kernel data cached in the L1D, potentially exposing the data over a covert channel.                                                                                                                                                                                                                                                                                                                                                |
| CVE-2017-5753 (Bounds Check Bypass, BCB, Spectre v1)                               | \[No CWE\] Systems with microprocessors utilizing speculative execution and indirect branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis of the data cache.                                                         | \[CWE-A\] Microarchitectural conditional branch predictors may allow operations to execute transiently after a misprediction, potentially exposing data over a covert channel.                                                                                                                                                                                                                                                                                                                          |
| CVE-2017-5754 (Branch Target Injection, BTI, Spectre v2)                           | \[No CWE\] Systems with microprocessors utilizing speculative execution and indirect branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis of the data cache.                                                         | \[CWE-D\] Shared microarchitectural indirect branch predictor state may allow code to influence transient execution across a process, VM, or privilege boundary, potentially exposing data that is accessible beyond the boundary over a covert channel.                                                                                                                                                                                                                                                |
| CVE-2018-3639 (Speculative Store Bypass, SSB, Spectre v4)                          | \[No CWE\] Systems with microprocessors utilizing speculative execution and speculative execution of memory reads before the addresses of all prior memory writes are known may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis.      | \[CWE-A\] Microarchitectural memory disambiguation predictors may allow operations with stale data to execute transiently, potentially exposing data over a covert channel.                                                                                                                                                                                                                                                                                                                             |
| CVE-2018-3640 (Rogue System Register Read, RSRE, Spectre v3a)                      | \[No CWE\] Systems with microprocessors utilizing speculative execution and that perform speculative reads of system registers may allow unauthorized disclosure of system parameters to an attacker with local user access via a side-channel analysis.                                             | \[CWE-B\] A fault may allow transient user-mode operations to access system register data, potentially exposing the data over a covert channel.                                                                                                                                                                                                                                                                                                                                                         |
| CVE-2018-3615 (L1 Terminal Fault, L1TF – SGX, Foreshadow)                          | \[No CWE\] Systems with microprocessors utilizing speculative execution and Intel® software guard extensions (Intel® SGX) may allow unauthorized disclosure of information residing in the L1 data cache from an enclave to an attacker with local user access via a side-channel analysis.          | \[CWE-B\] A fault may allow transient non-enclave operations to access SGX enclave data cached in the L1D, potentially exposing the data over a covert channel.                                                                                                                                                                                                                                                                                                                                         |
| CVE-2018-3620 (L1 Terminal Fault, L1TF – OS/SMM)                                   | \[No CWE\] Systems with microprocessors utilizing speculative execution and address translations may allow unauthorized disclosure of information residing in the L1 data cache to an attacker with local user access via a terminal page fault and a side-channel analysis.                         | \[CWE-B\] A fault may allow transient user-mode operations to access OS/SMM data cached in the L1D, potentially exposing the data over a covert channel.                                                                                                                                                                                                                                                                                                                                                |
| CVE-2018-3646 (L1 Terminal Fault, L1TF – VMM)                                      | \[No CWE\] Systems with microprocessors utilizing speculative execution and address translations may allow unauthorized disclosure of information residing in the L1 data cache to an attacker with local user access with guest OS privilege via a terminal page fault and a side-channel analysis. | \[CWE-B\] A fault may allow transient user-mode/guest operations to access VMM data cached in the L1D, potentially exposing the data over a covert channel.                                                                                                                                                                                                                                                                                                                                             |
| CVE-2018-12126 (Microarchitectural Store Buffer Data Sampling, MSBDS, Fallout)     | \[No CWE\] Store buffers on some microprocessors utilizing speculative execution may allow an authenticated user to potentially enable information disclosure via a side channel with local access.                                                                                                  | \[CWE-B\] A fault or microcode assist may allow transient operations to access architecturally restricted data in a microarchitectural store buffer, potentially exposing the data over a covert channel.                                                                                                                                                                                                                                                                                               |
| CVE-2018-12127 (Microarchitectural Load Port Data Sampling, MLPDS, RIDL)           | \[No CWE\] Load ports on some microprocessors utilizing speculative execution may allow an authenticated user to potentially enable information disclosure via a side channel with local access.                                                                                                     | \[CWE-B\] A fault or microcode assist may allow transient operations to access architecturally restricted data in a microarchitectural load port, potentially exposing the data over a covert channel.                                                                                                                                                                                                                                                                                                  |
| CVE-2018-12130 (Microarchitectural Fill Buffer Data Sampling, MFBDS, ZombieLoad)   | \[No CWE\] Fill buffers on some microprocessors utilizing speculative execution may allow an authenticated user to potentially enable information disclosure via a side channel with local access.                                                                                                   | \[CWE-B\] A fault or microcode assist may allow transient operations to access architecturally restricted data in a microarchitectural fill buffer, potentially exposing the data over a covert channel.                                                                                                                                                                                                                                                                                                |
| CVE-2019-11091 (Microarchitectural Data Sampling from Uncacheable Memory, MDSUM)   | \[No CWE\] Uncacheable memory on some microprocessors utilizing speculative execution may allow an authenticated user to potentially enable information disclosure via a side channel with local access.                                                                                             | \[CWE-B\] A fault or microcode assist may allow transient reads from uncacheable (UC) memory to access architecturally restricted data, potentially exposing the data over a covert channel.                                                                                                                                                                                                                                                                                                            |
| CVE-2019-1135 (TSX Asynchronous Abort, TAA)                                        | \[No CWE\] TSX Asynchronous Abort condition on some CPUs utilizing speculative execution may allow an authenticated user to potentially enable information disclosure via a side channel with local access.                                                                                          | \[CWE-B\] A TSX Asynchronous Abort may allow transient operations to access architecturally restricted data, potentially exposing the data over a covert channel.                                                                                                                                                                                                                                                                                                                                       |
| CVE-2020-0543 (Special Register Buffer Data Sampling, SRBDS, Crosstalk)            | \[No CWE\] Incomplete cleanup from specific special register read operations in some Intel(R) Processors may allow an authenticated user to potentially enable information disclosure via local access.                                                                                              | \[CWE-B\] A fault, microcode assist, or abort may allow transient operations to access special register data, potentially exposing the data over a covert channel.                                                                                                                                                                                                                                                                                                                                      |
| CVE-2020-0548 (Vector Register Sampling)                                           | \[No CWE\] Cleanup errors in some Intel® Processors may allow an authenticated user to potentially enable information disclosure via local access.                                                                                                                                                   | \[CWE-B\] A fault or microcode assist may allow transient operations to access architecturally restricted data in a microarchitectural vector register, potentially exposing the data over a covert channel.                                                                                                                                                                                                                                                                                            |
| CVE-2020-0549 (L1D Eviction Sampling)                                              | \[No CWE\] Cleanup errors in some data cache evictions for some Intel® Processors may allow an authenticated user to potentially enable information disclosure via local access.                                                                                                                     | \[CWE-B\] A fault, microcode assist, or abort may allow transient operations to access data in the L1D that the actor is not permitted to access, potentially exposing the data over a covert channel.                                                                                                                                                                                                                                                                                                  |
| CVE-2020-0550 (Snoop-assisted L1D)                                                 | \[No CWE\] Improper data forwarding in some data cache for some Intel® Processors may allow an authenticated user to potentially enable information disclosure via local access.                                                                                                                     | \[CWE-B\] A fault, microcode assist, or abort may allow transient operations to access architecturally restricted data in the L1D, potentially exposing the data over a covert channel.                                                                                                                                                                                                                                                                                                                 |
| CVE-2020-0551 (Load Value Injection, LVI)                                          | \[No CWE\] Load value injection in some Intel(R) Processors utilizing speculative execution may allow an authenticated user to potentially enable information disclosure via a side channel with local access.                                                                                       | \[CWE-C\] A fault, microcode assist, or abort may allow transient load operations to forward malicious stale data to dependent operations executed by a victim, causing the victim to unintentionally access and potentially expose its own data over a covert channel.                                                                                                                                                                                                                                 |
| CVE-2020-8698 (Fast Store Forwarding Predictor)                                    | \[CWE-1303\] Improper isolation of shared resources in some Intel(R) Processors may allow an authenticated user to potentially enable information disclosure via local access.                                                                                                                       | \[CWE-C on processors w/o cross-thread/domain training\] A fast store forwarding predictor may allow store operations to forward incorrect data to transient load operations, potentially exposing data over a covert channel; \[CWE-D on processors w/ cross-thread/domain training\] Shared fast store forwarding predictor state may allow code to influence transient execution across a hardware boundary, potentially exposing data that is accessible beyond the boundary over a covert channel. |
| CVE-2020-12965 (Transient Execution of Non-canonical Accesses)                     | \[No CWE\] When combined with specific software sequences, AMD CPUs may transiently execute non-canonical loads and store using only the lower 48 address bits potentially resulting in data leakage.                                                                                                | \[CWE-A\] A processor event or prediction may allow non-canonical loads and stores to execute transiently using only the lower 48 address bits, potentially exposing data over a covert channel.                                                                                                                                                                                                                                                                                                        |
| CVE-2021-0086 (Floating-Point Value Injection, FPVI)                               | \[CWE-204\] Observable response discrepancy in floating-point operations for some Intel® Processors may allow an authorized user to potentially enable information disclosure via local access.                                                                                                      | \[CWE-A\] A microcode assist may cause certain floating-point operations to execute transiently and produce incorrect outputs, potentially exposing data over a covert channel.                                                                                                                                                                                                                                                                                                                         |
| CVE-2021-0089 (Speculative Code Store Bypass, SCSB)                                | \[CWE-204\] Observable response discrepancy in some Intel® Processors may allow an authorized user to potentially enable information disclosure via local access.                                                                                                                                    | \[CWE-A\] A machine clear triggered by self-modifying code may allow incorrect operations to execute transiently, potentially exposing data over a covert channel.                                                                                                                                                                                                                                                                                                                                      |
| CVE-2021-33149 (Speculative Load Disordering, SLD, Speculative Cross-Store Bypass) | \[CWE-205\] Observable behavioral discrepancy in some Intel® Processors may allow an authorized user to potentially enable information disclosure via local access.                                                                                                                                  | \[CWE-C\] A machine clear triggered by a memory ordering violation may allow operations to execute transiently with stale data, potentially exposing data over a covert channel.                                                                                                                                                                                                                                                                                                                        |
| CVE-2022-0001 (Branch History Injection, BHI, Spectre-BHB)                         | \[CWE-1303\] Non-transparent sharing of branch predictor selectors between contexts in some Intel® Processors may allow an authorized user to potentially enable information disclosure via local access.                                                                                            | \[CWE-D\] Shared branch history state may allow user-mode code to influence transient execution in the kernel, potentially exposing kernel data over a covert channel.                                                                                                                                                                                                                                                                                                                                  |
| CVE-2022-0002 (Intra-mode Branch Target Injection, IMBTI)                          | \[CWE-1303\] Non-transparent sharing of branch predictor within a context in some Intel® Processors may allow an authorized user to potentially enable information disclosure via local access.                                                                                                      | \[CWE-A\] Microarchitectural indirect branch predictors may allow incorrect operations to execute transiently after a misprediction, potentially exposing data over a covert channel.                                                                                                                                                                                                                                                                                                                   |
| CVE-2022-29901 (RSB underflow, Retbleed)                                           | \[CWE-1303\] Non-transparent sharing of branch predictor targets between contexts in some Intel® Processors may allow an authorized user to potentially enable information disclosure via local access.                                                                                              | \[CWE-D for processors w/o eIBRS\] Shared microarchitectural return stack buffer state may allow user-mode code to influence transient execution in the kernel, potentially exposing kernel data over a covert channel; \[CWE-A for processors w/ eIBRS\] RSB alternate behavior may allow incorrect operations to execute transiently after an indirect branch misprediction, potentially exposing data over a covert channel.                                                                         |
| CVE-2022-26373 (Post-barrier RSB)                                                  | \[CWE-1303\] Non-transparent sharing of return predictor targets between contexts in some Intel® Processors may allow an authorized user to potentially enable information disclosure via local access.                                                                                              | \[CWE-D\] Shared return stack buffer state may allow code that executes before a prediction barrier to influence transient execution after the prediction barrier, potentially exposing data that is accessible beyond the barrier over a covert channel.                                                                                                                                                                                                                                               |
| CVE-2022-40982 (Gather Data Sampling)                                              | \[CWE-1303\] Information exposure through microarchitectural state after transient execution in certain vector execution units for some Intel(R) Processors may allow an authenticated user to potentially enable information disclosure via local access.                                           | \[CWE-B\] A fault may allow transient vector gather operations to access architecturally restricted data in a microarchitectural vector register file, potentially exposing the data over a covert channel.                                                                                                                                                                                                                                                                                             |

## References

1.  MITRE, "About CWE," 27 September 2022. \[Online\]. Available:
    https://cwe.mitre.org/about/index.html. \[Accessed 16 November
    2022\].

2.  O. Kirzner and A. Morrison, "An Analysis of Speculative Type
    Confusion Vulnerabilities in the Wild," in *30th USENIX Security
    Symposium (USENIX Security 21)*, 2021.

3.  M. Schwarz, M. Schwarzl, M. Lipp, J. Masters and D. Gruss,
    "NetSpectre: Read Arbitrary Memory over Network," in *ESORICS
    2019: 24th European Symposium on Research in Computer Security*,
    Luxembourg, Luxembourg, 2019.

4.  Intel Corporation., "Refined Speculative Execution Terminology,"
    Intel, 5 April 2021. \[Online\]. Available:
    https://www.intel.com/content/www/us/en/developer/articles/technical/softwaresecurity-guidance/best-practices/refined-speculative-execution-terminology.html.

5.  Intel Corporation, "Intel® 64 and IA-32 Architectures Software
    Developer Manuals," 2022 30 September. \[Online\]. Available:
    https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html.
    \[Accessed 2022 21 November\].

6.  AMD, "Developer Guides, Manuals & ISA Documents," \[Online\].
    Available:
    https://developer.amd.com/resources/developer-guides-manuals/.
    \[Accessed 21 November 2022\].
