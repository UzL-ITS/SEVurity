# Abstract 
One reason for not adopting cloud services is the required trust in the cloud provider: As they control the hypervisor, any data processed in the system is accessible to them. Full memory encryption for Virtual Machines (VM) protects against curious cloud providers as well as otherwise compromised hypervisors. AMD Secure Encrypted Virtualization (SEV) is the most prevalent hardware-based full memory encryption for VMs. Its newest extension, SEV-ES, also protects the entire VM state during context switches, aiming to ensure that the host neither learns anything about the data that is processed inside the VM, nor is able to modify its execution state. Several previous works have analyzed the security of SEV and have shown that, by controlling I/O, it is possible to exfiltrate data or even gain control over the VM's execution. In this work, we introduce two new methods that allow us to inject arbitrary code into SEV-ES secured virtual machines. Due to the lack of proper integrity protection, it is sufficient to reuse existing ciphertext to build a high-speed encryption oracle. As a result, our attack no longer depends on control over the I/O, which is needed by prior attacks. As I/O manipulation is highly detectable, our attacks are stealthier. In addition, we reverse-engineer the previously unknown, improved Xor-Encrypt-Xor (XEX) based encryption mode, that AMD is using on updated processors, and show, for the first time, how it can be overcome by our new attacks. 
# Videos

## IEESP Teaser
<iframe width="560" height="315" src="https://www.youtube-nocookie.com/embed/F-cetzHWYOs" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

## IEESP Presentation
<iframe width="560" height="315" src="https://www.youtube-nocookie.com/embed/_y3D8pINDyA" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>


# Cite
```
@INPROCEEDINGS {9152717,
author = {L. Wilke and J. Wichelmann and M. Morbitzer and T. Eisenbarth},
booktitle = {2020 IEEE Symposium on Security and Privacy (SP)},
title = {SEVurity: No Security Without Integrity : Breaking Integrity-Free Memory Encryption with Minimal Assumptions},
year = {2020},
volume = {},
issn = {},
pages = {1483-1496},
keywords = {encryption;virtual machine monitors;random access memory;cloud computing;program processors},
doi = {10.1109/SP40000.2020.00080},
url = {https://doi.ieeecomputersociety.org/10.1109/SP40000.2020.00080},
publisher = {IEEE Computer Society},
address = {Los Alamitos, CA, USA},
month = {may}
}
```
