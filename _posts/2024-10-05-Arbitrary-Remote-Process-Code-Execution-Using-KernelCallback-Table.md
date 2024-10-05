---
layout: "post"
title : "Arbitrary Remote Process Code Execution Using KernelCallbackTable"
comments: true
---

Recently I was researching new code execution techniques to use in my own projects and I came across the KernelCallbackTable injection technique.

This technique, which is usually used in malware production, allows us to inject our own malicious shellcode into a victim program and manipulate the code flow of this program and run our own malicious codes in the background.

When I researched this technique, I saw that it was previously used in malware called [**Lazarus**](https://www.threatdown.com/blog/north-koreas-lazarus-apt-leverages-windows-update-client-github-in-latest-campaign/)  and [**FınSpy**](https://www.microsoft.com/en-us/security/blog/2018/03/01/finfisher-exposed-a-researchers-tale-of-defeating-traps-tricks-and-complex-virtual-machines/).



{% include disqus.html %}