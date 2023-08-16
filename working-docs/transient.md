New CWEs for Transient Execution
================================

A proposal by Intel, in collaboration with MITRE and the CWE community

Motivation and Overview
--------------------------------

Common Weakness Enumeration (CWE) is “a community-developed list of
common software and hardware weakness types that have security
ramifications” \[1\]. Common Vulnerability Enumeration (CVE) is a list
of publicly known vulnerabilities. Each CVE is an instance of a CWE. For
example,
[CVE-2021-43618](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-43618)
is “GNU Multiple Precision Arithmetic Library (GMP) through 6.2.1 has an
`mpz/inp\_raw.c` integer overflow and resultant buffer overflow via
crafted input, leading to a segmentation fault on 32-bit platforms.”
This CVE is an instance of
[CWE-787](https://cwe.mitre.org/data/definitions/787.html), whose
description reads “The software writes data past the end, or before the
beginning, of the intended buffer.”

Whenever an organization (such as Intel) issues a CVE for a new
transient execution attack, its description is expected to borrow
language from an existing CWE. The following table summarizes CWEs that
pertain to transient execution attacks.

| CWE                                                      | Title                                                                             | Description                                                                                                                                                                               |
| -------------------------------------------------------- | --------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [1037](https://cwe.mitre.org/data/definitions/1037.html) | Processor Optimization Removal or Modification of Security-critical Code          | The developer builds a security-critical protection mechanism into the software, but the processor optimizes the execution of the program such that the mechanism is removed or modified. |
| [1264](https://cwe.mitre.org/data/definitions/1264.html) | Hardware Logic with Insecure De-Synchronization between Control and Data Channels | The hardware logic for error handling and security checks can incorrectly forward data before the security check is complete.                                                             |
| [1303](https://cwe.mitre.org/data/definitions/1303.html) | Non-Transparent Sharing of Microarchitectural Resources                           | Hardware structures shared across execution contexts (e.g., caches and branch predictors) can violate the expected architecture isolation between contexts.                               |
| [1342](https://cwe.mitre.org/data/definitions/1342.html) | Information Exposure through Microarchitectural State after Transient Execution   | The processor does not properly clear microarchitectural state after incorrect microcode assists or speculative execution, resulting in transient execution.                              |

These existing CWEs do not address the root causes of transient
execution attacks, and therefore do not suffice to characterize them.
For example, consider
[CVE-2017-5753](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5753)
(Bounds Check Bypass, or BCB):

  - Although BCB can affect conditional branches that do serve as
    “security-critical protection mechanisms” (for example, in
    software sandboxes), BCB can also affect branches that serve a
    functional purpose, such as dynamic type checking \[2\]. Therefore
    CWE-1037 is too narrow.

  - The conditional branch instructions affected by BCB are not
    “hardware logic for error handling and security checks.” Hence
    CWE-1264 does not apply.

  - BCB can be exploited over a network \[3\] without shared hardware
    resources, and therefore CWE-1303 does not apply.

  - CWE-1342 implies that the processor should be clearing
    microarchitectural state, which is impractical or infeasible for
    many vulnerabilities, including BCB.

This document aims to define **five** new CWEs that address the root causes of
transient execution attacks, and with language that is sufficiently generic to
benefit the entire CWE community.

New CWE Proposals
--------------------------------

### CWE-A: Transient Execution

#### Description

A processor event or prediction may allow incorrect operations (or correct
operations with incorrect data) to execute transiently, potentially exposing
data over a microarchitectural covert channel.

#### Extended Description

When operations execute but do not commit to the processor’s architectural
state, this is commonly referred to as *transient execution*. This behavior can
occur when the processor mis-predicts an outcome (such as a branch target), or
when a processor event (such as an exception) is signaled after younger
operations have already executed. Operations that execute transiently may have
microarchitectural side effects that can be detected using timing or power
analysis techniques. These techniques may allow an attacker to infer information
about the operations that executed transiently. For example, the attacker may be
able to infer program data that was accessed or used by those operations.

#### Relationships

- Parent of CWE-B
- Parent of CWE-C
- Parent of CWE-D
- Parent of CWE-E

#### Examples

1. Speculative Code Store Bypass (SCSB)
2. Speculative Load Disordering (SLD)

### CWE-B: Transient Execution Allows Access to Data in a Shared Microarchitectural Structure

#### Description

A processor event (for example, a hardware exception) may allow transient
operations to access another user's data in a shared microarchitectural
structure (for example, a CPU cache), potentially exposing the data.

#### Extended Description

Many commodity processors have Instruction Set Architecture (ISA) features that
protect software components from one another. These features can include memory
segmentation, virtual memory, privilege rings, trusted execution environments,
and virtual machines, among others. For example, virtual memory provides each
process with its own address space, which prevents processes from accessing one
another's private data.

When transient operations allow access to data that is protected by the ISA,
this can violate users' expectations of the ISA feature that is bypassed. For
example, if transient operations can access a victim's private data in a shared
microarchitectural structure, then the operations' microarchitectural side
effects may correspond to the accessed data. If an attacker is able to trigger
these transient operations and observe their side effects through a covert
channel, then the attacker may be able to infer the victim's data.

#### Relationships

- Child of CWE-A

#### Examples

- Rogue Data Cache Load (RDCL, also known as Meltdown)
- L1 Terminal Fault (L1TF, also known as Foreshadow)

### CWE-C: Processor Event Causes Incorrect Data to be Forwarded to Operations that Execute Transiently

#### Description

A processor event (for example, a hardware exception) may allow transient
operations to forward incorrect or stale data to dependent operations,
potentially exposing the data.

#### Extended Description

Software may use a variety of techniques to preserve the confidentiality of
private data that is accessible within the current processor context. For
example, the memory safety and type safety properties of some high-level
programming languages help to prevent software written in those languages from
exposing private data. As a second example, software sandboxes may co-locate
multiple users' software within a single process. One user's software may be
permitted by the processor's Instruction Set Architecture (ISA) to access
another user's data (because the software shares the same address space), but
the sandbox prevents these accesses by using software techniques such as bounds
checking and address masking.

If transient operations can forward incorrect or stale data to dependent
operations, then the dependent operations' microarchitectural side effects may
correspond to the data.  If an attacker is able to trigger these transient
operations and observe their side effects through a covert channel, then the
attacker may be able to infer the data. For example, an attacker process may
induce transient execution in a victim process that causes the victim to
inadvertently access and then expose its private data via a covert channel. In
the software sandbox example, an attacker sandbox may induce transient execution
in its own code, allowing it to transiently access and expose data in a victim
sandbox that shares the same process.

When transient operations can forward incorrect or stale data to dependent
operations, this can violate users' expectations of the software's security. If
the transient execution behavior that allows the access is not properly
documented by the hardware vendor, this can violate the software vendor's
expectation of how the hardware should behave.

#### Relationships

- Child of CWE-A

#### Examples

1. Floating-point Value Injection (FPVI)

### CWE-D: Transient Execution Influenced by Shared Microarchitectural Predictor State

#### Description

Shared microarchitectural predictor state may allow code to influence transient
execution across a hardware boundary, potentially exposing data that is
accessible beyond the boundary.

#### Extended Description

Many commodity processors have Instruction Set Architecture (ISA) features that
protect software components from one another. These features can include memory
segmentation, virtual memory, privilege rings, trusted execution environments,
and virtual machines, among others. For example, virtual memory provides each
process with its own address space, which prevents processes from accessing one
another's private data. Many of these features can be used to form
hardware-enforced security boundaries between software components. 

When separate software components (for example, two processes) share
microarchitectural predictor state across a hardware boundary, code in one
component may be able to influence microarchitectural predictor behavior in
another component. If the predictor can cause transient execution, then shared
predictor state may allow an attacker to influence transient execution in a
victim, and in a manner that could allow the attacker to infer private data from
the victim.

Predictor state may be shared when the processor transitions from one component
to another (for example, when a process makes a system call to enter the
kernel). Many commodity processors have features which prevent
microarchitectural predictions that occur before a boundary from influencing
predictions that occur after the boundary. These features may be always-on, on
by default, or may require opt-in from software.

Predictor state may also be shared between hardware threads (for example,
sibling SMT threads). This sharing may be benign if the hardware threads are
simultaneously executing in the same software component, or it could expose a
vulnerability if it allows different software components to share predictor
state. Processors that share microarchitectural predictors between hardware
threads may have features that prevent microarchitectural predictions that occur
on one hardware thread from influencing predictions that occur on another
hardware thread. Similar to the features that prevent sharing across
transitions, these features may be always-on, on by default, or may require
opt-in from software.

#### Relationships

- Child of CWE-A

#### Examples

1. Branch Target Injection (BTI)
2. Branch History Injection (BHI)

### CWE-E: Transient Execution Caused by Microarchitectural Predictor

#### Description

Microarchitectural predictors may allow operations to execute transiently after
a misprediction, potentially exposing data.

#### Extended Description

Many commodity processors use microarchitectural predictors (for example, branch
predictors) to improve performance. After a misprediction, the processor may
continue to execute operations until it discovers that the prediction was
incorrect, at which point it will discard the architectural results of those
operations. However, if these *transient* operations can access data
protected by hardware or software, then the operations' microarchitectural side
effects may correspond to the data. If an attacker is able to trigger these
transient operations and observe their side effects through a covert channel,
then the attacker may be able to infer the data.  Moreover, if the predictor's
transient execution behavior is not properly documented by the hardware vendor,
this can violate software vendors' expectations of how the hardware should
behave.

Some commodity processors may provide features that prevent microarchitectural
predictors from allowing program data to become inferable by an attacker. For
example, a processor may allow software to opt-in to temporarily disable a
microarchitectural predictor. Many processors also provide serialization
instructions that can be used by software to prevent predictions made prior to
the serialization instruction from causing transient execution after the
instruction. Some modern compilers can be directed to automatically instrument
their output to mitigate the effects of transient execution caused by
microarchitectural predictors.

Developers of sandbox or managed runtime software should exercise caution when
relying on software techniques (such as bounds checking) to prevent code in one
sandbox from accessing private data in another sandbox. For example, an attacker
sandbox may be able to train a microarchitectural predictor in a manner that
allows it to transiently read a victim sandbox's private data. As a second
example, an attacker may be able to train a microarchitectural predictor in a
manner that causes the victim to inadvertently access and then expose its
private data via a covert channel. In most cases these vulnerabilities can be
mitigated by using hardware to protect sandboxes from one another (for example,
by deploying each sandbox in a separate process).

#### Relationships

- Child of CWE-A

#### Examples

1. Bounds Check Bypass (BCB)
2. Speculative Store Bypass (SSB)

Author’s Notes
--------------------------------

### Notes About this Updated Proposal

  - The term "confused deputy" would be useful to describe some exploits that could fall within CWE-B and CWE-D, but this term does not appear in the CWE glossary. This term could be useful for other CWEs as well.
  - The novel term "hardware domain" was removed from this proposal. This term is difficult to define and, once defined, becomes too rigid. Instead, this proposal contrasts "data protected by hardware" with "data protected by software." This revised language is intended to provide hardware designers with flexibility to specify what their hardware is intended to protect.

### Notes about the Original Proposal

  - When writing these descriptions, I have tried as much as possible to
    avoid introducing new terms, or terms that are specific to Intel’s
    literature/documentation.
    
      - Intel often uses “malicious adversary,” but here I have used
        “attacker” to align with the [CWE
        glossary](https://cwe.mitre.org/documents/glossary/).
    
      - “Transient,” “transient execution,” “transient operations,” etc.
        do not exist in the CWE glossary but have been used in other
        CWEs. I had initially drafted these descriptions without using
        the word “transient,” but this often led to unappealing
        verbosity—I had to spell out “operations that execute but do not
        commit to architectural state” many times. Perhaps MITRE should
        consider adding “transient” to its CWE glossary.
    
      - I make liberal use of the term “processor event,” which is
        intended to convey “something that happens while the processor
        is executing operations.” This could be anything from a fault to
        a snoop assist.
    
      - The concept of a hardware domain is essential to CWE-C. Intel’s
        documentation defines a hardware domain as “code and data within
        a protection boundary that is defined by hardware-enforced
        access control mechanisms such as privilege level (ring), page
        tables, and protection keys” \[4\]. Intel has used this term in
        the past, but I’m not sure about the extent to which it is used
        by other organizations.
    
      - There were several places where I thought “victim” might be a
        good word, but I noticed that “victim” does not appear in the
        CWE glossary (a little strange, given that “attacker” does
        appear).
    
      - I didn’t find “logical processor” in the CWE glossary, though it
        is a term common to at least Intel \[5\] and AMD \[6\] public
        documentation. So I thought it would be OK to include it where
        relevant.

  - I have intentionally abstained from using “side channel” or “covert
    channel” in the descriptions. Every transient execution attack that
    I am aware of uses a covert channel, but this component of the
    attack is independent from the root cause, which is a processor
    event that causes transient execution. CWE-203 and its descendants
    are adequate to cover side channels and covert channels
    independently from CWEs A, B, C, and D herein.

  - I have tried my best to adhere to the guidelines provided by MITRE
    (see Appendix):
    
      - **Name:** Each CWE name is intended to focus on the weakness,
        not a specific attack. Each name hints at the weakness category
        (“Transient” or “Transient Execution”) and the affected
        technology (“Processor” or “Microarchitecture”). CWE-C applies
        to a specific kind of resource, “shared microarchitectural
        predictor state,” which is included in the name.
    
      - **Summary:** Each summary is intended to describe the weakness
        itself in a single sentence. Following MITRE’s guidelines, I
        have avoided focusing on any particular attack, the absence of a
        mitigation, and the potential impact.
    
      - **Extended Description:** Following MITRE’s guidelines, I have
        used the extended descriptions to highlight potential impacts
        for developers, and to generalize the mitigation strategies that
        have been adopted throughout the industry.

Applying These New CWEs to A Variety of Transient Execution CVEs
----------------------------------------------------------------

The following is a partial survey of existing CVEs that pertain
to transient execution. Each entry in the table compares the current CVE
description against a hypothetical CVE description that derives from the
draft CWE language introduced earlier in this document. Note that many
CVEs issued prior to 2021 did not use CWE descriptions, indicated by
“\[No CWE\].”

| CVE                                                                                | Current Description                                                                                                                                                                                                                                                                                  | New Description                                                                                                                                                                                                                                                                                                      |
| ---------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CVE-2017-5715 (Rogue Data Cache Load, RDCL, Meltdown, Variant 3)                   | \[No CWE\] Systems with microprocessors utilizing speculative execution and indirect branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis of the data cache.                                                         | \[CWE-B\] A fault may allow transient user-mode operations to access kernel data cached in the L1D, potentially exposing the data. |
| CVE-2017-5753 (Bounds Check Bypass, BCB, Spectre v1)                               | \[No CWE\] Systems with microprocessors utilizing speculative execution and indirect branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis of the data cache.                                                         | \[CWE-E\] Microarchitectural conditional branch predictors may allow operations to execute transiently after a misprediction, potentially exposing data.  |
| CVE-2017-5754 (Branch Target Injection, BTI, Spectre v2)                           | \[No CWE\] Systems with microprocessors utilizing speculative execution and indirect branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis of the data cache.                                                         | \[CWE-D\] Shared microarchitectural indirect branch predictor state may allow code to influence transient execution across a process, VM, or privilege boundary, potentially exposing data that is accessible beyond the boundary. |
| CVE-2018-3639 (Speculative Store Bypass, SSB, Spectre v4)                          | \[No CWE\] Systems with microprocessors utilizing speculative execution and speculative execution of memory reads before the addresses of all prior memory writes are known may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis.      | \[CWE-E\] Microarchitectural memory disambiguation predictors may allow operations to execute transiently after a misprediction, potentially exposing data. |
| CVE-2018-3640 (Rogue System Register Read, RSRE, Spectre v3a)                      | \[No CWE\] Systems with microprocessors utilizing speculative execution and that perform speculative reads of system registers may allow unauthorized disclosure of system parameters to an attacker with local user access via a side-channel analysis.                                             | \[CWE-B\] A fault may allow transient user-mode operations to access system register data, potentially exposing the data. |
| CVE-2018-3615 (L1 Terminal Fault, L1TF – SGX, Foreshadow)                          | \[No CWE\] Systems with microprocessors utilizing speculative execution and Intel® software guard extensions (Intel® SGX) may allow unauthorized disclosure of information residing in the L1 data cache from an enclave to an attacker with local user access via a side-channel analysis.          | \[CWE-B\] A fault may allow transient non-enclave operations to access SGX enclave data, potentially exposing the data. |
| CVE-2018-3620 (L1 Terminal Fault, L1TF – OS/SMM)                                   | \[No CWE\] Systems with microprocessors utilizing speculative execution and address translations may allow unauthorized disclosure of information residing in the L1 data cache to an attacker with local user access via a terminal page fault and a side-channel analysis.                         | \[CWE-B\] A fault may allow transient user-mode operations to access OS/SMM data, potentially exposing the data. |
| CVE-2018-3646 (L1 Terminal Fault, L1TF – VMM)                                      | \[No CWE\] Systems with microprocessors utilizing speculative execution and address translations may allow unauthorized disclosure of information residing in the L1 data cache to an attacker with local user access with guest OS privilege via a terminal page fault and a side-channel analysis. | \[CWE-B\] A fault may allow transient user-mode/guest operations to access VMM data, potentially exposing the data. |
| CVE-2018-12126 (Microarchitectural Store Buffer Data Sampling, MSBDS, Fallout)     | \[No CWE\] Store buffers on some microprocessors utilizing speculative execution may allow an authenticated user to potentially enable information disclosure via a side channel with local access.                                                                                                  | \[CWE-B\] A fault or microcode assist may allow transient operations to access data that the actor is not permitted to access via a microarchitectural store buffer, potentially exposing the data. |
| CVE-2018-12127 (Microarchitectural Load Port Data Sampling, MLPDS, RIDL)           | \[No CWE\] Load ports on some microprocessors utilizing speculative execution may allow an authenticated user to potentially enable information disclosure via a side channel with local access.                                                                                                     | \[CWE-B\] A fault or microcode assist may allow transient operations to access data that the actor is not permitted to access via a microarchitectural load port, potentially exposing the data. |
| CVE-2018-12130 (Microarchitectural Fill Buffer Data Sampling, MFBDS, ZombieLoad)   | \[No CWE\] Fill buffers on some microprocessors utilizing speculative execution may allow an authenticated user to potentially enable information disclosure via a side channel with local access.                                                                                                   | \[CWE-B\] A fault or microcode assist may allow transient operations to access data that the actor is not permitted to access via a microarchitectural fill buffer, potentially exposing the data. |
| CVE-2019-11091 (Microarchitectural Data Sampling from Uncacheable Memory, MDSUM)   | \[No CWE\] Uncacheable memory on some microprocessors utilizing speculative execution may allow an authenticated user to potentially enable information disclosure via a side channel with local access.                                                                                             | \[CWE-B\] A fault or microcode assist may allow transient reads from uncacheable (UC) memory to access data that the actor is not permitted to access, potentially exposing the data. |
| CVE-2019-1135 (TSX Asynchronous Abort, TAA)                                        | \[No CWE\] TSX Asynchronous Abort condition on some CPUs utilizing speculative execution may allow an authenticated user to potentially enable information disclosure via a side channel with local access.                                                                                          | \[CWE-B\] A TSX Asynchronous Abort may allow transient operations to access that the actor is not permitted to access, potentially exposing the data. |
| CVE-2020-0543 (Special Register Buffer Data Sampling, SRBDS, Crosstalk)            | \[No CWE\] Incomplete cleanup from specific special register read operations in some Intel(R) Processors may allow an authenticated user to potentially enable information disclosure via local access.                                                                                              | \[CWE-B\] A fault, microcode assist, or abort may allow transient operations to access special register data, potentially exposing the data |
| CVE-2020-0548 (Vector Register Sampling)                                           | \[No CWE\] Cleanup errors in some Intel® Processors may allow an authenticated user to potentially enable information disclosure via local access.                                                                                                                                                   | \[CWE-B\] A fault or microcode assist may allow transient operations to access stale vector register data that the actor is not permitted to access, potentially exposing the data.
| CVE-2020-0549 (L1D Eviction Sampling)                                              | \[No CWE\] Cleanup errors in some data cache evictions for some Intel® Processors may allow an authenticated user to potentially enable information disclosure via local access.                                                                                                                     | \[CWE-B\] A fault, microcode assist, or abort may allow transient operations to access data in the L1D that the actor is not permitted to access, potentially exposing the data.
| CVE-2020-0550 (Snoop-assisted L1D)                                                 | \[No CWE\] Improper data forwarding in some data cache for some Intel® Processors may allow an authenticated user to potentially enable information disclosure via local access.                                                                                                                     | \[CWE-B\] A fault, microcode assist, or abort may allow transient operations to access data in the L1D that the actor is not permitted to access, potentially exposing the data. |
| CVE-2020-0551 (Load Value Injection, LVI)                                          | \[No CWE\] Load value injection in some Intel(R) Processors utilizing speculative execution may allow an authenticated user to potentially enable information disclosure via a side channel with local access.                                                                                       | \[CWE-C\] A fault, microcode assist, or abort may allow a malicious actor to inject data into transient load operations executed by a victim, causing the victim to unintentionally access and potentially expose its own data. |
| CVE-2021-0086 (Floating-Point Value Injection, FPVI)                               | \[CWE-204\] Observable response discrepancy in floating-point operations for some Intel® Processors may allow an authorized user to potentially enable information disclosure via local access.                                                                                                      | \[CWE-C\] A microcode assist may allow a malicious actor to inject data into transient floating-point operations executed by a victim, causing the victim to access and potentially expose its own data. |
| CVE-2021-0089 (Speculative Code Store Bypass, SCSB)                                | \[CWE-204\] Observable response discrepancy in some Intel® Processors may allow an authorized user to potentially enable information disclosure via local access.                                                                                                                                    | \[CWE-A\] A machine clear triggered by self-modifying code may allow incorrect operations to execute transiently, potentially exposing data. |
| CVE-2021-33149 (Speculative Load Disordering, SLD, Speculative Cross-Store Bypass) | \[CWE-205\] Observable behavioral discrepancy in some Intel® Processors may allow an authorized user to potentially enable information disclosure via local access.                                                                                                                                  | \[CWE-A\] A machine clear triggered by a memory ordering violation may allow transient operations to access stale data, potentially exposing the data. |
| CVE-2022-0001 (Branch History Injection, BHI, Spectre-BHB)                         | \[CWE-1303\] Non-transparent sharing of branch predictor selectors between contexts in some Intel® Processors may allow an authorized user to potentially enable information disclosure via local access.                                                                                            | \[CWE-D\] Shared branch history state may allow user-mode code to influence transient execution in the kernel, potentially exposing kernel data. |
| CVE-2022-0002 (Intra-mode Branch Target Injection, IMBTI)                          | \[CWE-1303\] Non-transparent sharing of branch predictor within a context in some Intel® Processors may allow an authorized user to potentially enable information disclosure via local access.                                                                                                      | \[CWE-E\] Microarchitectural indirect branch predictors may allow incorrect operations to execute transiently after a misprediction, potentially exposing data.                                                                                                                                                                                 |
| CVE-2022-29901 (RSB underflow, Retbleed)                                           | \[CWE-1303\] Non-transparent sharing of branch predictor targets between contexts in some Intel® Processors may allow an authorized user to potentially enable information disclosure via local access.                                                                                              | \[CWE-D for processors w/o eIBRS\] Shared microarchitectural return stack buffer state may allow user-mode code to influence transient execution in the kernel, potentially exposing kernel data; \[CWE-E for processors w/ eIBRS\] RSB alternate behavior may allow incorrect operations to execute transiently after an indirect branch misprediction, potentially exposing data. |
| CVE-2022-26373 (Post-barrier RSB)                                                  | \[CWE-1303\] Non-transparent sharing of return predictor targets between contexts in some Intel® Processors may allow an authorized user to potentially enable information disclosure via local access.                                                                                              | \[CWE-D\] Shared return stack buffer state may allow code that executes before a prediction barrier to influence transient execution after the prediction barrier, potentially exposing data that is accessible beyond the barrier. |

References
--------------------------------

1.  MITRE, "About CWE," 27 September 2022. \[Online\]. Available:
    https://cwe.mitre.org/about/index.html. \[Accessed 16 November
    2022\].

2.  O. Kirzner and A. Morrison, "An Analysis of Speculative Type
    Confusion Vulnerabilities in the Wild," in *30th USENIX Security
    Symposium (USENIX Security 21)*, 2021.

3.  M. Schwarz, M. Schwarzl, M. Lipp, J. Masters and D. Gruss,
    "NetSpectre: Read Arbitrary Memory over Network," in *ESORICS 2019:
    24th European Symposium on Research in Computer Security*,
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

Appendix
--------------------------------

### Submission Guidelines for Individual Elements (Provided by MITRE)

#### Name

Ideally, the name focuses on the weakness/mistake - not the attack.
Minimize use of ambiguous words to keep the name short. Where feasible,
use terminology as defined in the CWE glossary and/or vulnerability
theory documents. The name should include: (1) the intended behavior of
the code, (2) the mistake (i.e. weakness), (3) the affected resource (if
relevant), and (4) the affected technology (if relevant).

#### Summary

The summary consists of only one or two sentences that describe the
weakness itself, i.e. the mistake that is made. Often, the summary will
describe what the developer/designer is attempting to do. Critical parts
of the summary include: (1) the intended behavior of the code, (2) the
mistake (i.e. weakness), (3) the affected resource (if relevant), and
(4) the affected technology (if relevant). Each summary part is only
expressed with individual words or brief phrases; the extended
description can be more comprehensive in its explanation.

The summary (and name) should avoid focusing on: (1) the attack, (2) the
absence of a mitigation, or (3) the technical impact. If a summary has a
strong reliance on this information, this may be an indicator that the
entry is not weakness-focused.

#### Extended Description

The extended description provides additional explanation for the
weakness. Generally, the intended audience is a developer/designer who
might not immediately understand how the weakness can be a problem, or
who may have an overly simplistic understanding of the problem.

The extended description may consist of multiple paragraphs, but
typically it is only one or two paragraphs long.

The extended description:

  - Explains why the weakness should be a concern to the
    developer/designer.

  - Briefly summarizes the technical impact that could result.

  - Gives subtleties or variations that are necessary to have a broader
    understanding of the issue.
