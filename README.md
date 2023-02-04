# AMSI-patches-learned-till-now
I have documented all of the AMSI patches that I learned till now

## :exclamation: My AMSI patch Learning till now. Doesn't belong to my Company's Asset!

### DISCLAIMER: This code is not meant to be Evasive till now! Only a Conceptual Approach.

### Links:
1. https://pre.empt.dev/posts/maelstrom-etw-amsi/#Antimalware_Scan_Interface_(AMSI)
2. https://rastamouse.me/memory-patching-amsi-bypass/ 

### Still remaining to be Implemented:
1. Patching AMSI via **Hardware Breakpoint** and **VEH**: [In-Process Patchless AMSI Bypass](https://ethicalchaos.dev/2022/04/17/in-process-patchless-amsi-bypass/)

### Image:

![Capture](https://user-images.githubusercontent.com/61424547/216752409-be8f1120-c1e0-4052-b950-69ac0b020eaf.PNG)

#### One of the Way of patching AMSI:

![AMSI_patch](https://user-images.githubusercontent.com/61424547/216752741-9fb198ad-c041-43d4-af2b-1118086fa43c.PNG)

### Concepts:

### 1. ***AmsiOpenSession***: Opens a session within which multiple scan requests can be correlated.

a. To Skip Entering _`amsi!AmsiOpenSession+0x4c`_ via _jne_, if all instructions succeed before the calling of _jne_\
=> We would end up directly to _`amsi!AmsiCloseSession`_.

Video link: https://drive.google.com/file/d/1H0JheGNGzIyWZ62HNLmJ_oeAAUtDGIKd/view?usp=sharing

#### Thanks to [@D1rkMtr](https://twitter.com/D1rkMtr/) for showing the technique of using `jne` from _`amsi!AmsiOpenSession`_ [Github](https://github.com/TheD1rkMtr/AMSI_patch). I have used his AMSI patch code template and added other methods I have worked on till now.

b. To Skip Entering _`amsi!AmsiOpenSession+0x4c`_ (Opens a session within which multiple scan requests can be correlated) via _ret_, by directly pasting _c3_ at the beginning of the _`amsi!AmsiOpenSession`_\
=> We would end up directly to _`amsi!AmsiCloseSession`_.

Video link: https://drive.google.com/file/d/1_tpCfJ-aO1wzeEx3Id7b7bTJUyc5ExBw/view?usp=sharing

### 2. ***AmsiScanBuffer***: Scans a buffer-full of content for malware.

a. To Skip the execution of the main intructions of _`amsi!AmsiScanBuffer`_ via _ret_, by directly pasting _c3_ at the beginning of the `amsi!AmsiScanBuffer`

Video link: https://drive.google.com/file/d/1PljZld1aXz89nCO3gQCjYpwSqbEbi4J_/view?usp=sharing

b. To Skip the branch that does the actual scanning in _`amsi!AmsiScanBuffer`_ and returns, by directly pasting `\\xB8\\x57\\x00\\x07\\x80\\xC3` ('mov eax, 0x80070057; ret') at the beginning of the _`amsi!AmsiScanBuffer`_

Here, the value (rather error Value) of HRESULT being 'E_INVALIDARG' (Source: https://pre.empt.dev/posts/maelstrom-etw-amsi/#Historic_AMSI_Bypasses)

#### Thanks to [@_RastaMouse](https://twitter.com/_RastaMouse)_ for this [blog](https://rastamouse.me/memory-patching-amsi-bypass/)

c. To Skip the branch that does the actual scanning in _`amsi!AmsiScanBuffer`_ and returns, by directly pasting `\\xB8\\x05\\x00\\x07\\x80\\xC3` ('mov eax, 0x80070005; ret') at the beginning of the _`amsi!AmsiScanBuffer`_

Here, the value (rather error Value) of HRESULT being 'E_ACCESSDENIED' (Source: https://pre.empt.dev/posts/maelstrom-etw-amsi/#Historic_AMSI_Bypasses)

d. To Skip the branch that does the actual scanning in _`amsi!AmsiScanBuffer`_ and returns, by directly pasting `\\xB8\\x06\\x00\\x07\\x80\\xC3` ('mov eax, 0x80070006; ret') at the beginning of the _`amsi!AmsiScanBuffer`_

Here, the value (rather error Value) of HRESULT being 'E_HANDLE' (Source: https://pre.empt.dev/posts/maelstrom-etw-amsi/#Historic_AMSI_Bypasses)

e. To Skip the branch that does the actual scanning in _`amsi!AmsiScanBuffer`_ and returns, by directly pasting `\\xB8\\x0E\\x00\\x07\\x80\\xC3` ('mov eax, 0x8007000E; ret') at the beginning of the _`amsi!AmsiScanBuffer`_

Here, the value (rather error Value) of HRESULT being 'E_OUTOFMEMORY' (Source: https://pre.empt.dev/posts/maelstrom-etw-amsi/#Historic_AMSI_Bypasses)
