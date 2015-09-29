kb_exp.pl: reads kb.xml and outputs all QID that have exploits associated, uses PERL and XML::Twig, run with perl kb_exp.pl

kb.xml: simple testfile with 1 QID

Demo run:
<pre><code>
wkandek$ curl -o kb.xml -u qXXXXXX1 https://qualysapi.qg2.apps.qualys.com/msp/knowledgebase_download.php

Enter host password for user 'qXXXXXX1':

   % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current        
100 93.3M    0 93.3M    0     0   186k      0 --:--:--  0:08:31 --:--:--  146k 

wkandek$ perl kb_exp.pl > exploits.lst 

wkandek$ wc exploits.lst
     6119    6119   40759 exploits.lst 

wkandek$ head -3 exploits.lst 
118131 
13006 
116672 

wkandek$ tail -3 exploits.lst 
195410 
115779 
38429
</code></pre>
