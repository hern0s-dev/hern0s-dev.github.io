---
layout: post
title : "Arbitrary Remote Process Code Execution Using KernelCallbackTable"
comments: true
---

## Some Information About Technique
Recently I was researching new code execution techniques to use in my own projects and I came across the KernelCallbackTable injection technique.

This technique, which is usually used in malware production, allows us to inject our own malicious shellcode into a victim program and manipulate the code flow of this program and run our own malicious codes in the background.



When I researched this technique, I saw that it was previously used in malware called [**Lazarus**](https://www.threatdown.com/blog/north-koreas-lazarus-apt-leverages-windows-update-client-github-in-latest-campaign/)  and [**FinSpy**](https://www.microsoft.com/en-us/security/blog/2018/03/01/finfisher-exposed-a-researchers-tale-of-defeating-traps-tricks-and-complex-virtual-machines/).

<div id="disqus_thread"></div>
<script>
    /**
    *  RECOMMENDED CONFIGURATION VARIABLES: EDIT AND UNCOMMENT THE SECTION BELOW TO INSERT DYNAMIC VALUES FROM YOUR PLATFORM OR CMS.
    *  LEARN WHY DEFINING THESE VARIABLES IS IMPORTANT: https://disqus.com/admin/universalcode/#configuration-variables    */
    /*
     var disqus_config = function () {
    this.page.url = "{{ site.url }}{{ page.url }}"; // Replace PAGE_URL with your page's canonical URL variable
    this.page.identifier = "{{ page.url }}"; // Replace PAGE_IDENTIFIER with your page's unique identifier variable 
    };
    */
 
    (function() { // DON'T EDIT BELOW THIS LINE
    var d = document, s = d.createElement('script');
    s.src = 'https://https-hern0s-dev-github-io.disqus.com/embed.js';
    s.setAttribute('data-timestamp', +new Date());
    (d.head || d.body).appendChild(s);
    })();
</script>
<noscript>Please enable JavaScript to view the <a href="https://disqus.com/?ref_noscript">comments powered by Disqus.</a></noscript>

