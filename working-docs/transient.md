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

The objective of this document is to define
**<span class="underline">four</span>** new CWEs that address the root
causes of transient execution attacks, and with language that is
sufficiently generic to benefit the entire CWE community.

New CWE Proposals
--------------------------------

### CWE-A: Processor Event Causes Transient Execution

#### Description

A processor event may allow subsequent operations to execute transiently
(the operations execute without committing to architectural state).

#### Extended Description

Many commodity processors execute operations (such as instructions,
etc.) out-of-order. For example, a processor may fetch the sequence of
instructions `A;B;C`, but then execute them in a different order, such as
`A;C;B`. This out-of-order execution sequence may produce the same result
as an in-order sequence if the input to `C` does not depend on the output
of `B`. Although operations on these processors may execute out-of-order,
they commit in-order to the processor’s architectural state. Hence, all
operations appear to software as though they had been executed in-order
by the processor.

Some processor events can cause an out-of-order processor to flush its
pipeline, discarding the results of operations that have already
executed but not committed to the processor’s architectural state. For
example, suppose that while executing `B` in the out-of-order sequence
`A;C;B`, the processor encounters an event that causes a pipeline flush.
If `C` executed before `B`, the event may require `C`’s results to be
discarded during the flush.

When operations execute but do not commit to the processor’s
architectural state, this is commonly referred to as *transient
execution*. Operations that execute transiently may have
microarchitectural side effects that can be detected using timing or
power analysis techniques. These techniques may allow an attacker to
infer information about the operations that executed transiently. For
example, the attacker may be able to infer program data that was
accessed or used by those operations.

### CWE-B: Transient Data Forwarding from an Operation that Triggers a Processor Event

#### Description

A processor event (for example, a fault or microcode assist) may allow
incorrect data to be forwarded from the operation that triggered the
event to operations that execute transiently.

#### Extended Description

Commodity processors may require assistance from microcode (or other
processor design techniques) to execute certain operations. For example,
processors that implement virtual memory may use microcode to perform
virtual-to-physical address translation, check for faults, etc. Prior to
or concurrent with the microcode assist, some processors may allow
incorrect data to be forwarded from the operation that triggered the
assist to operations that execute transiently and are flushed by the
time the assist completes. These transient operations can affect
observable microarchitectural state in a manner that could allow an
attacker to infer program data, such as the incorrect data forwarded by
the operation that triggered the assist.

### CWE-C: Transient Execution Influenced by Shared Microarchitectural Predictor State

#### Description

Shared microarchitectural predictor state may allow code in one hardware
domain to influence transient execution in another domain.

#### Extended Description

When hardware domains (for example, processes or privilege rings) share
microarchitectural predictor state, code in one domain may be able to
influence microarchitectural predictor behavior in another domain. If
the predictor can cause transient execution, then shared predictor state
may allow an attacker to influence transient execution in an
attacker-chosen domain, and in a manner that could allow the attacker to
infer program data from that domain.

Many commodity processors have features which prevent microarchitectural
predictions that occur before a domain transition from influencing
predictions that occur after the domain transition. These features may
be always-on, on by default, or may require opt-in from software.

Some commodity processors may also share microarchitectural predictors
(possibly including predictor state) between logical processors. These
processors may have features that prevent microarchitectural predictions
that occur on one logical processor from influencing predictions that
occur on another logical processor. Similar to the features that prevent
sharing across domain transitions, these features may be always-on, on
by default, or may require opt-in from software.

### CWE-D: Microarchitectural Predictor Causes Transient Execution

#### Description

Microarchitectural predictors may allow incorrect operations (or correct
operations with incorrect data) to execute transiently after a
misprediction.

#### Extended Description

Many commodity processors use microarchitectural predictors (for
example, branch predictors) to improve performance. Operations that
execute after a misprediction are not committed to the processor’s
architectural state and their results are discarded. However, these
transient operations can affect observable microarchitectural state in a
manner that could allow an attacker to infer program data.

Some commodity processors may provide features that prevent
microarchitectural predictors from allowing program data to become
inferable by an attacker. For example, a processor may allow software to
opt-in to temporarily disable a microarchitectural predictor. Many
instruction set architectures also provide serialization instructions
that can be used by software to prevent predictions made prior to the
serialization instruction from causing transient execution after the
instruction. Some modern compilers can be directed to automatically
instrument their output to mitigate the effects of transient execution
caused by microarchitectural predictors, especially branch predictors.

Developers of sandbox or managed runtime software should exercise
caution when allowing multiple users to run code within the same
hardware domain. For example, one user’s code may be able to train a
microarchitectural predictor in a manner that allows it to transiently
read another user’s data. As a second example, one user’s code may be
able to train a microarchitectural predictor in a manner that influences
transient execution when another user runs code, potentially causing
that user’s data to become inferable. In most cases, these weaknesses
can be mitigated by isolating each user’s code and data in separate
hardware domains.

Author’s Notes
--------------------------------

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

Applying These New CWEs to Intel’s Transient Execution CVEs
-----------------------------------------------------------

The following is a partial survey of Intel’s existing CVEs that pertain
to transient execution. Each entry in the table compares the current CVE
description against a hypothetical CVE description that derives from the
draft CWE language introduced earlier in this document. Note that many
CVEs issued prior to 2021 did not use CWE descriptions, indicated by
“\[No CWE\].”

| CVE                                                                                | Current Description                                                                                                                                                                                                                                                                                  | New Description                                                                                                                                                                                                                                                                                                      |
| ---------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CVE-2017-5715 (Rogue Data Cache Load, RDCL, Meltdown, Variant 3)                   | \[No CWE\] Systems with microprocessors utilizing speculative execution and indirect branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis of the data cache.                                                         | \[CWE-B\] A fault may allow data in the L1D to be forwarded from the operation that triggered the fault to operations that execute transiently.                                                                                                                                                                      |
| CVE-2017-5753 (Bounds Check Bypass, BCB, Spectre v1)                               | \[No CWE\] Systems with microprocessors utilizing speculative execution and indirect branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis of the data cache.                                                         | \[CWE-D\] Microarchitectural conditional branch predictors may allow incorrect operations to execute transiently after a misprediction.                                                                                                                                                                              |
| CVE-2017-5754 (Branch Target Injection, BTI, Spectre v2)                           | \[No CWE\] Systems with microprocessors utilizing speculative execution and indirect branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis of the data cache.                                                         | \[CWE-C\] Shared indirect branch predictor state may allow code in one hardware domain to influence transient execution in another domain.                                                                                                                                                                           |
| CVE-2018-3639 (Speculative Store Bypass, SSB, Spectre v4)                          | \[No CWE\] Systems with microprocessors utilizing speculative execution and speculative execution of memory reads before the addresses of all prior memory writes are known may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis.      | \[CWE-D\] Microarchitectural memory disambiguation predictors may allow operations to execute transiently with stale data after a misprediction.                                                                                                                                                                     |
| CVE-2018-3640 (Rogue System Register Read, RSRE, Spectre v3a)                      | \[No CWE\] Systems with microprocessors utilizing speculative execution and that perform speculative reads of system registers may allow unauthorized disclosure of system parameters to an attacker with local user access via a side-channel analysis.                                             | \[CWE-B\] A fault may allow system register data to be forwarded from the operation that triggered the fault to operations that execute transiently.                                                                                                                                                                 |
| CVE-2018-3615 (L1 Terminal Fault, L1TF – SGX, Foreshadow)                          | \[No CWE\] Systems with microprocessors utilizing speculative execution and Intel® software guard extensions (Intel® SGX) may allow unauthorized disclosure of information residing in the L1 data cache from an enclave to an attacker with local user access via a side-channel analysis.          | \[CWE-B\] A fault may allow SGX enclave data to be forwarded from the operation that triggered the fault to operations that execute transiently.                                                                                                                                                                     |
| CVE-2018-3620 (L1 Terminal Fault, L1TF – OS/SMM)                                   | \[No CWE\] Systems with microprocessors utilizing speculative execution and address translations may allow unauthorized disclosure of information residing in the L1 data cache to an attacker with local user access via a terminal page fault and a side-channel analysis.                         | \[CWE-B\] A fault may allow OS/SMM data to be forwarded from the operation that triggered the fault to operations that execute transiently.                                                                                                                                                                          |
| CVE-2018-3646 (L1 Terminal Fault, L1TF – VMM)                                      | \[No CWE\] Systems with microprocessors utilizing speculative execution and address translations may allow unauthorized disclosure of information residing in the L1 data cache to an attacker with local user access with guest OS privilege via a terminal page fault and a side-channel analysis. | \[CWE-B\] A fault may allow VMM data to be forwarded from the operation that triggered the fault to operations that execute transiently.                                                                                                                                                                             |
| CVE-2018-12126 (Microarchitectural Store Buffer Data Sampling, MSBDS, Fallout)     | \[No CWE\] Store buffers on some microprocessors utilizing speculative execution may allow an authenticated user to potentially enable information disclosure via a side channel with local access.                                                                                                  | \[CWE-B\] A fault or microcode assist in some Intel® processors may allow stale data in a store buffer to be forwarded from a load operation to operations that execute transiently.                                                                                                                                 |
| CVE-2018-12127 (Microarchitectural Load Port Data Sampling, MLPDS, RIDL)           | \[No CWE\] Load ports on some microprocessors utilizing speculative execution may allow an authenticated user to potentially enable information disclosure via a side channel with local access.                                                                                                     | \[CWE-B\] A fault or microcode assist in some Intel® processors may allow stale data in a load port to be forwarded from a load operation to operations that execute transiently.                                                                                                                                    |
| CVE-2018-12130 (Microarchitectural Fill Buffer Data Sampling, MFBDS, ZombieLoad)   | \[No CWE\] Fill buffers on some microprocessors utilizing speculative execution may allow an authenticated user to potentially enable information disclosure via a side channel with local access.                                                                                                   | \[CWE-B\] A fault or microcode assist in some Intel® processors may allow stale data in a fill buffer to be forwarded from a load operation to operations that execute transiently.                                                                                                                                  |
| CVE-2019-11091 (Microarchitectural Data Sampling from Uncacheable Memory, MDSUM)   | \[No CWE\] Uncacheable memory on some microprocessors utilizing speculative execution may allow an authenticated user to potentially enable information disclosure via a side channel with local access.                                                                                             | \[CWE-B\] A fault or microcode assist in some Intel® processors may allow incorrect data to be forwarded from a load operation to operations that execute transiently.                                                                                                                                               |
| CVE-2019-1135 (TSX Asynchronous Abort, TAA)                                        | \[No CWE\] TSX Asynchronous Abort condition on some CPUs utilizing speculative execution may allow an authenticated user to potentially enable information disclosure via a side channel with local access.                                                                                          | \[CWE-B\] A TSX Asynchronous Abort in some Intel® processors may allow stale data to be forwarded from a load operation to operations that execute transiently.                                                                                                                                                      |
| CVE-2020-0543 (Special Register Buffer Data Sampling, SRBDS, Crosstalk)            | \[No CWE\] Incomplete cleanup from specific special register read operations in some Intel(R) Processors may allow an authenticated user to potentially enable information disclosure via local access.                                                                                              | \[CWE-B\] A fault, microcode assist, or abort in some Intel® processors may allow special register data to be forwarded from a load operation to operations that execute transiently.                                                                                                                                |
| CVE-2020-0548 (Vector Register Sampling)                                           | \[No CWE\] Cleanup errors in some Intel® Processors may allow an authenticated user to potentially enable information disclosure via local access.                                                                                                                                                   | \[CWE-B\] A fault, microcode assist, or abort in some Intel® processors may allow data from a vector register to be forwarded from a load operation to operations that execute transiently.                                                                                                                          |
| CVE-2020-0549 (L1D Eviction Sampling)                                              | \[No CWE\] Cleanup errors in some data cache evictions for some Intel® Processors may allow an authenticated user to potentially enable information disclosure via local access.                                                                                                                     | \[CWE-B\] A fault, microcode assist, or abort in some Intel® processors may allow data from the L1D cache to be forwarded from a load operation to operations that execute transiently.                                                                                                                              |
| CVE-2020-0550 (Snoop-assisted L1D)                                                 | \[No CWE\] Improper data forwarding in some data cache for some Intel® Processors may allow an authenticated user to potentially enable information disclosure via local access.                                                                                                                     | \[CWE-B\] A fault, microcode assist, or abort in some Intel® processors may allow data from the L1D cache to be forwarded from a load operation to operations that execute transiently.                                                                                                                              |
| CVE-2020-0551 (Load Value Injection, LVI)                                          | \[No CWE\] Load value injection in some Intel(R) Processors utilizing speculative execution may allow an authenticated user to potentially enable information disclosure via a side channel with local access.                                                                                       | \[CWE-B\] A fault, microcode assist, or abort in some Intel® processors may allow incorrect data to be forwarded from a load operation to operations that execute transiently.                                                                                                                                       |
| CVE-2021-0086 (Floating-Point Value Injection, FPVI)                               | \[CWE-204\] Observable response discrepancy in floating-point operations for some Intel® Processors may allow an authorized user to potentially enable information disclosure via local access.                                                                                                      | \[CWE-B\] A microcode assist in some Intel® processors may allow incorrect data to be forwarded from a floating-point operation to operations that execute transiently.                                                                                                                                              |
| CVE-2021-0089 (Speculative Code Store Bypass, SCSB)                                | \[CWE-204\] Observable response discrepancy in some Intel® Processors may allow an authorized user to potentially enable information disclosure via local access.                                                                                                                                    | \[CWE-A\] A machine clear triggered by self-modifying code may allow subsequent operations to execute transiently.                                                                                                                                                                                                   |
| CVE-2021-33149 (Speculative Load Disordering, SLD, Speculative Cross-Store Bypass) | \[CWE-205\] Observable behavioral discrepancy in some Intel® Processors may allow an authorized user to potentially enable information disclosure via local access.                                                                                                                                  | \[CWE-A\] A machine clear triggered by a memory ordering violation may allow subsequent operations to execute transiently.                                                                                                                                                                                           |
| CVE-2022-0001 (Branch History Injection, BHI, Spectre-BHB)                         | \[CWE-1303\] Non-transparent sharing of branch predictor selectors between contexts in some Intel® Processors may allow an authorized user to potentially enable information disclosure via local access.                                                                                            | \[CWE-C\] Shared branch history state may allow code in one hardware domain to influence transient execution in another domain.                                                                                                                                                                                      |
| CVE-2022-0002 (Intra-mode Branch Target Injection, IMBTI)                          | \[CWE-1303\] Non-transparent sharing of branch predictor within a context in some Intel® Processors may allow an authorized user to potentially enable information disclosure via local access.                                                                                                      | \[CWE-D\] Microarchitectural indirect branch predictors may allow incorrect operations to execute transiently after a misprediction.                                                                                                                                                                                 |
| CVE-2022-29901 (RSB underflow, Retbleed)                                           | \[CWE-1303\] Non-transparent sharing of branch predictor targets between contexts in some Intel® Processors may allow an authorized user to potentially enable information disclosure via local access.                                                                                              | \[CWE-C for processors w/o eIBRS\] Shared return stack buffer state may allow code in one hardware domain to influence transient execution in another domain; \[CWE-D for processors w/ eIBRS\] RSB alternate behavior may allow incorrect operations to execute transiently after an indirect branch misprediction. |
| CVE-2022-26373 (Post-barrier RSB)                                                  | \[CWE-1303\] Non-transparent sharing of return predictor targets between contexts in some Intel® Processors may allow an authorized user to potentially enable information disclosure via local access.                                                                                              | \[CWE-C\] Shared return stack buffer state may allow code that executes before a prediction barrier to influence transient execution after the prediction barrier.                                                                                                                                                   |

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
