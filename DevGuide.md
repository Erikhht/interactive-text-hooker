# Introduction #
This article describe the process of custom hook devloping and H-code format. Reader should be familiar with x86 architecture, assembly and debuggers.

# What ITH does #
When perform attach operation, ITH will inject a DLL into target process. The DLL then insert hooks within the target process address space. Since x86 is Von Neumann architecture. Program code resides in the same address space as program data. So if coded carefully, read/write certain part of memory can change the program's execution flow. After a hook is inserted at a certain address, whenver the program execute the instruction at that address, it will first execute hook code. ITH insert hook as follow:

1. Disassemble instruction length at the target address, make sure it's greater than 5.<br>
2. Copy the instructions to somewhere else for later recovery.<br>
3. Allocate memory and fill it with hook code. <br>
4. Modify instrution at the target process to CALL $(E8 $), where $ stands for the hook code entry address. The call instruction is 5 bytes long, if we copied more than 5 bytes, fill the rest with INT 3(CC).<br>
5. Copy original instruction after hook code, do necessary modifications(any position relative instruction, jmp,call, etc)<br>
and insert a JMP $(E9) at the end. Here $ stands for the next instruction at the target address.<br>
<br>
Assume 1-10 is address of 10 instruction. If insert hook at 5 and hook code at 15-20. The execution flow will be 1-4, jmp to 15, 15-20, 5, jmp back to 6, 6-10.<br>
This technique let you intercept program execution, and do anything you want at that point. ITH applies this technique to text processing related routes to intercept text. At a certain point ITH can<br>
<ul><li>Read all register value<br>
</li><li>Access most memory except the stack above current ESP.</li></ul>

<h1>Information needed to build hook</h1>
<ul><li>Address data indicating where to insert hook.<br>
</li><li>Text data(whether it reside in register or at some memory location)<br>
</li><li>Text data processing information (Endian, Unicode, String...)<br>
</li><li>Split data if necessary (when text with different meaning processed at one place).</li></ul>

<h1>Encoding of information</h1>
AGTH H-code is an efficient method to encode this information.<br>
Although it's not complete in theory, it can handle most of common cases. When text processing is too complicated to represent by H-code, an extern hook is needed. That is, we provide our own code to gather information for ITH.<br>
<h3>H-code format</h3>
<pre><code>/H{A|B|W|S|Q}[N][data_offset[*data_indirect]][:split_param[*split_indirect]]@addr[:module[:name]]<br>
</code></pre>
/H: Prefix for H-code.<br>
A|B|W|S|Q: Data form.<br>
N: Disable(zero) first split parameter. By default, the first split parameter is taken from <code>[ESP]</code>.<br>
data_offset: Specify where to find data. If data_offset is positive, data is taken from <code>[ESP+data_offset]</code>. If data_offset is negative, it refers to registers as follow.<br>
<br>
<table><thead><th> <b>EAX</b> </th><th> <b>ECX</b> </th><th> <b>EDX</b> </th><th> <b>EBX</b> </th><th> <b>ESP</b> </th><th> <b>EBP</b> </th><th> <b>ESI</b> </th><th> <b>EDI</b> </th></thead><tbody>
<tr><td> -4         </td><td> -8         </td><td> -C         </td><td> -10        </td><td> -14        </td><td> -18        </td><td> -1C        </td><td> -20        </td></tr></tbody></table>

data_indirect: If value of data_offset is a pointer, use this to take one level of indirection reference. Assume 32-bit pointer taken according to data_offset is off_data. So data is taken from <code>[off_data+data_indirect]</code>.<br>
split_param, split_indirect: Same to data_offset, but value is for split parameter.<br>
addr: Absolute address or offset.<br>
module: Target module name. Case insensitive.<br>
name: Export function name. Case sensitive.<br>
<br>
Some examples:<br>
<code>/HA-4@41F400</code> -> SHIFT-JIS character in EAX, 8? at AH.<br>
<code>/HS4@CE1F0:koisora_main.exe</code> -> If koisora_main is mapped at 400000, insert address is 400000+CE1F0=10E1F0. <code>[ESP+4]</code> contains a SHIFT-JIS string pointer.<br>
<code>/HWN-10*-8:-10*10@46AE28</code> -> Unicode character at <code>[EBX-8]</code>, split parameter at <code>[EBX+10]</code>, zero default split parameter.<br>
<br>
<br>
<h1>Valid address form</h1>
Most of current H-codes use absolute address(@address). It's resolved to the correspond address in target process virtual address space. Base-offset(@offset:base) is a more flexible form. You specify a module name as base address, and an offset to add to that base. This form is necessary if you are hooking in DLL or the main module is using Address Space Layout Randomization. You can also specify a function name in the export table of target module to narrow down the address.<br>
<h1>Valid data form</h1>
<h3>SHIFT-JIS</h3>
Most game engines use SHIFT-JIS encoding. SHIFT-JIS characters begins from 8140. Usually 2 bytes long. If you see a 2 byte data 8??? or 9???, it's probably a SHIFT-JIS character. If 8? is at high address, use A, otherwise use B to represent SHIFT-JIS character<br>
<h3>Unicode</h3>
There are also many engines using Unicode encoding. Japanese character (Hiragana and Katakata)in Unicode starts from 3000. But Kanji characters spread in a great range. Unicode characters are always 2 bytes long. Look for 2 bytes data with the form 30?? is good. Use W to represent Unicode character.<br>
<h3>String</h3>
If you find a big block of text and is null terminated, you can use string. S for SHIFT-JIS and Q for Unicode. Note that value is a pointer of the first character. So there is already a level of indirection.<br>
<br>
<h1>Valid split parameter form</h1>
There is no fixed format for split parameter. Split parameter is used to split text stream from one hook into different threads. It's only necessary to be different if you want to split the text.<br>
<br>
<h1>Examples</h1>
Now I take some examples to demonstrate the whole process to build a hook.<br>
1. Font caching issue<br>
Example BGI engine. 素晴らしき日々<br>
Default hook gives a thread from TextOutA. Set breakpoint at TextOutA.<br>
Called from 41F1F2. We navigate to the entry of current function -- 41F1A0. Set a breakpoint there and let the process fly. We can observe that process breaks at 41F1A0 as many times as TextOutA. So we continue step out. 41F1A0 is called from 41F45A. Entry of this function is 41F400. This time process breaks at 41F400 more than TextOutA, as well as 41F1A0. At 41F400, EAX contains data we want. So the code is /HA-4@41F400. Then we discover that it mess up with some punctuation. Keep the breakpoint at 41F400 and clears all other. We can discover that ESP changes several times during one sentence, especially when the character is punctuation(for example 8141:、). So we use ESP as split parameter. H-code is /HA-4:-14@41F400. Simple test shows that this code works pretty well.