# Introduction #

Interactive Text Hooker (ITH) is a tool to help you extract text from Japanese games. It's the first building blocks of a auto-translating system. The main purpose of ITH is to intercept text processed by a program and arrange text into clean form. Main idea of ITH comes from AGTH. ITH works very like AGTH, and has some advantage over AGTH.

# System requirement #

Intel Pentium4 or later processor. Recommend OS is Windows XP or later.
Your processor must support SSE2. Or you may get an error message.

# Basic Usage #

## Setup and start ITH ##


ITH contains 3 files, namely ITH.exe, ITH.dll and ITH\_engine.dll. These 3 files need to be put into same folder. ITH requires administrative privilege to function properly. If you are using Vista/7, you need to run ITH as administrator.

## UI layout ##

The first line contains 8 buttons.<br>
<b>Process</b>: opens the <i>Process Explorer</i>.<br>
<b>Thread</b>: opens the <i>Thread Editor</i>.<br>
<b>Hook</b>: opens the <i>Hook Editor</i>.<br>
<b>Profile</b>: opens the <i>Profile Manager</i>.<br>
<b>Option</b>: opens the <i>Option Dialog</i>.<br>
<b>Top</b>: let ITH stay on top of other windows.<br>
<b>Clear</b>: clears text of current thread.<br>
<b>Save</b>: save current profile.<br>

The second line contains a short drop-down list and a editable area.<br>
The short drop-down list is called <i>Process List</i>. This list contains Process ID and name of all attached process.<br>
The editable area is called <i>Command Line</i>. You can type command here to let ITH perform actions.<br>
<br>
The third line is a long drop-down list called <i>Thread List</i>. This list contains all available thread. You can select one thread to change content of the <i>Text Area</i>.<br>
<br>
Under the <i>Thread List</i> is the <i>Text Area</i>. This area contains text of one thread.<br>
<h2>Attach ITH</h2>

The first step of text extraction is attaching ITH to a game. Open the <i>Process Explorer</i>. On the left you can see a list of processes that ITH is able to attach. This list is sorted by creation time of the process. So the latest created process is at the top of this list. Select the process you want to attach ITH, then click <b>Attach</b> button. ITH will give a message if it attach successfully. Click <b>OK</b> to close the dialog.<br>
<br>
<h2>Select text thread</h2>

After ITH receive some text, it will put text into <i>threads</i>. A <i>thread</i> contains certain piece of the text. If you select one from the <i>Thread List</i>, the text in the main window is changed to that thread. By default, there's only one named <b>ConsoleOutput</b>. Usually as the game display some text, more threads should be added to this list. If you can't see any thread other than ConsoleOutput while the game is flashing text, you will need to insert custom hook.<br>
<br>
<h2>Copy to clipboard</h2>

ITH can copy received text to clipboard, then other translation software monitors clipboard can read the text and translate it into other language. You can simply select text in the <i>Text Area</i> by clicking and dragging. Then the selected text is copied to clipboard. ITH is able to copy the last sentence to clipboard automatically. You need to enable this function in the <i>Option Dialog</i> by checking <b>Auto copy to clipboard</b>.<br>
<br>
<h2>Save you selection</h2>

It's bothersome to attach ITH and select text every time you start the game. After you have attached ITH and selected some thread for the first time, click <b>Save</b> to save your selection. ITH will record necessary information in ITH.pro. The next time you start this game, ITH will attach to the game and select thread automatically.<br>
<br>
<h2>Link threads together</h2>

When your see text appears in different threads, you don't need to switch between them every time. ITH provide a flexible mechanism to handle this case. Namely <i>Thread Linking</i>. You can find thread name in the <i>Thread List</i>. Every thread's name begins with its unique 4-digit identifier. You use this number to tell ITH which threads to link. Notice that thread number is hexadecimal. So character A-F stands for decimal number 10-15 (you won't see decimal number in <i>Thread List</i>). You will need 2 numbers to perform a link operation. Namely <i>From</i> and <i>To</i>. There are 2 ways to link threads.<br>
<ul><li>Open the <b>Thread Editor</b> by clicking <b>Thread</b>. Select thread with the number <i>From</i> from the list in the top. Select thread with the number <i>To</i> from the shorter list. Then click <b>Set</b>.<br>
</li><li>Type L"From"-"To" in the <i>Command Line</i> and press enter. No quotes, only number. Example LA-4.</li></ul>

<h2>Additional hook</h2>

If you couldn't get any useful text thread, you will have to insert additional hook to generate more threads. You need a small piece of text called <i>H-code</i> to inform ITH about the desired hook. <i>H-code</i> looks like this /HA-8:-14@402050. Type <i>H-code</i> in the <i>Command Line</i> and press enter, a new hook will be inserted. As the game goes advance, you may see new text threads in <i>Thread List</i>. This code is game and usually version dependent. To create such a code, you should be familiar with programming and x86 assembly. If you don't know what these things are, you must wait someone else to create one. You can request it at the Hongfire forum.