### Building the Card Conformance Tool from GitHub
#### Windows version

##### Java

- Uninstall all instances of Java.
- Remove all environment variables: `JAVA_HOME`, `JAVA_BIN`, `JAVA_LIB`.
- Install JDK 1.8_0_201.  Note where it's installed (probably `C:\Program Files\Java\jdk1.8_0_201` on Windows).
- Check your `PATH` variable and clean out any old Java remnants and ensure that it includes the new Java version's `bin` directory.
- Set your `JAVA_HOME` to the new JDK installation directory.  Add a `JAVA_BIN` set to `%JAVA_HOME%\bin` and `JAVA_HOME` set to `%JAVA_HOME%\lib`.
- Get a command window and test with `javac -version` and `java -version`.

##### Cygwin (recommended for Windows users)
- Install Cygwin from `https://cygwin.com`.

##### Git (optional)

- Install Git from `https://github.com/git-for-windows/git/releases/download/v2.21.0.windows.1/Git-2.21.0-64-bit.exe`.
- Ensure that the directory containing git.exe is in your PATH environment 
- To test, open a command window and type `git version`.
- This optional because the Buildship plugin in Eclipse will sometimes "lose" things, and the command line `git` is more reliable. 
-  Now, do this:
- `cd $HOME #(or cd %HOME%)`
- `mkdir -p ~/git/ #or whatever you do in DOS to achieve the same effect`
- `cd git`
- Make sure that you've set up Git to globally store your username and password:
- `git config --global user.name *your-username*`
- `git config --global user.email *your-email*`
- The first time you try to clone or push anything, you'll be asked for a password. Paste in your personal access token from GitHub for the box you are working from.
- `git clone https://github.com/GSA/piv-conformance.git piv-conformance`
- `cd piv-conformance`
- `sh doit.sh #this is where having Cygwin is handy because it uses Gradle to build everything)`
- If you don't have Cygwin, simply execute the `gradlew` commands in `doit.sh` in the same order.

##### Eclipse (EGit automagically built-in)

- Download the Eclipse desktop for Java (version 2019-03 for Win 64 is fine)
- Accept all licenses during installation and take all defaults.
- Accept the default workspace (probably eclipse-workspace) when you load it.
- Now, if you installed Git and pulled in a clone of the repo, you can import the project from Git by selecting your `~/git/piv-conformance` directory (or folder).
- If you didn't, then you give up some autonomy as to where your repos will be created.  On my system, I want my Git repos to live in `Documents\GitRepos` so that I can just back up Documents and not have to hunt all over the system for places that need to be backed up.  Eclipse will usually allow you to override it, but if you don't watch what you're doing, it'll want to put it in the `eclipse-workspace` directory.  If you are okay with that, then continue forward.
- Once you dismiss the Eclipse welcome tab the empty Eclipse appears.
- Select *Import project* and *Git -> Projects from Git*
- Again, if you've got your repo already cloned, then choose existing local repository.
- If not, then choose *Clone URI* and if you've got the URI above in your clipboard, it'll fill in the dialog box except for your GitHub credentials.  Because this is a GSA account, you won't be able to push anything but can create pull requests.
- Leave all of the defaults and provide your GitHub username and personal access token for your dev box to Eclipse (Egit plugin) and it will offer to store it.  You are best advised to take Eclipse up on that offer, or you'll be forever changing your personal access tokens.
- If you've done everything right, you'll see some 10-11 branches.  De-select all but `swing` and `swing-gui-devel`.
- After clicking Next, you'll be offered to choose `swing` as the default branch.  Choose `swing-gui-devel` instead.
- Clicking *Next* will clone the repo to wherever you specified on the previous screen.
- At this point, you don't have any Eclipse projects.  You've made Eclipse aware of a repo and that's all.
- Now, you should be able to import the existing Eclipse projects.  There are actually 4, but only 3 show up temporarily.
- Choose them all.  Also, select *Add project to working sets* and create a new working set called `piv-conformance` and add the projects to that working set.
- You'll see a lot of red X decorators because your local environment hasn't been pulled into Eclipse. We'll get to that in a moment.
- From the Outline window, select *Import* -> *General* -> *Projects* from Folder or Archive and click Next.
- Click Directory and choose `conformancelib` and Open.
- You'll see the *conformancelib* project greyed out. Click *Finish*.  You now have all 4 projects in Eclipse.
- Drop to the command window and ensure you are in the `piv-conformance` directory (or folder). 
- Now, if you have Cygwin, you can just type `sh doit.sh` and everything will be pulled in and built for you.
- If not, then look at `doit.sh` and type the commands in the same order
- You will see output like this:

```
bf-mbp:piv-conformance $ sh doit.sh

> Configure project :
target java version: 1.8
source java version: 1.8
Runtime dependencies:

BUILD SUCCESSFUL in 4s
1 actionable task: 1 up-to-date

> Configure project :
target java version: 1.8
source java version: 1.8
Runtime dependencies:

BUILD SUCCESSFUL in 1s
3 actionable tasks: 3 executed

> Configure project :
target java version: 1.8
source java version: 1.8
Runtime dependencies:

> Task :compileJava
Note: Some input files use unchecked or unsafe operations.
Note: Recompile with -Xlint:unchecked for details.

> Task :jar
/Users/Bob/.gradle/caches/modules-2/files-2.1/org.bouncycastle/bcpkix-jdk15on/1.59/9cef0aab8a4bb849a8476c058ce3ff302aba3fff/bcpkix-jdk15on-1.59.jar
/Users/Bob/.gradle/caches/modules-2/files-2.1/org.bouncycastle/bcprov-jdk15on/1.59/2507204241ab450456bdb8e8c0a8f986e418bd99/bcprov-jdk15on-1.59.jar
/Users/Bob/.gradle/caches/modules-2/files-2.1/commons-cli/commons-cli/1.4/c51c00206bb913cd8612b24abd9fa98ae89719b1/commons-cli-1.4.jar
/Users/Bob/.gradle/caches/modules-2/files-2.1/commons-codec/commons-codec/1.11/3acb4705652e16236558f0f4f2192cc33c3bd189/commons-codec-1.11.jar
/Users/Bob/.gradle/caches/modules-2/files-2.1/com.payneteasy/ber-tlv/1.0-8/51705ef33704586936446d96768bfee6849db00a/ber-tlv-1.0-8.jar
/Users/Bob/.gradle/caches/modules-2/files-2.1/ch.qos.logback/logback-classic/1.3.0-alpha4/2cd967bc8fbd5e5ebbb93abd0b254b1eaf90e471/logback-classic-1.3.0-alpha4.jar
/Users/Bob/.gradle/caches/modules-2/files-2.1/org.slf4j/slf4j-api/1.8.0-beta4/83b0359d847ee053d745be7ec0d8e9e8a44304b4/slf4j-api-1.8.0-beta4.jar
/Users/Bob/.gradle/caches/modules-2/files-2.1/org.xerial/sqlite-jdbc/3.21.0.1/81a0bcda2f100dc91dc402554f60ed2f696cded5/sqlite-jdbc-3.21.0.1.jar
/Users/Bob/.gradle/caches/modules-2/files-2.1/junit/junit/4.11/4e031bb61df09069aeb2bffb4019e7a5034a4ee0/junit-4.11.jar
/Users/Bob/.gradle/caches/modules-2/files-2.1/ch.qos.logback/logback-core/1.3.0-alpha4/3ec023a0068a02e5d4697fce3435562348d3d478/logback-core-1.3.0-alpha4.jar
/Users/Bob/.gradle/caches/modules-2/files-2.1/com.sun.mail/javax.mail/1.6.0/a055c648842c4954c1f7db7254f45d9ad565e278/javax.mail-1.6.0.jar
/Users/Bob/.gradle/caches/modules-2/files-2.1/org.hamcrest/hamcrest-core/1.3/42a25dc3219429f0e5d060061f71acb49bf010a0/hamcrest-core-1.3.jar
/Users/Bob/.gradle/caches/modules-2/files-2.1/javax.activation/activation/1.1/e6cb541461c2834bdea3eb920f1884d1eb508b50/activation-1.1.jar

BUILD SUCCESSFUL in 1s
6 actionable tasks: 6 executed

BUILD SUCCESSFUL in 0s
1 actionable task: 1 up-to-date

BUILD SUCCESSFUL in 0s
3 actionable tasks: 3 executed

Deprecated Gradle features were used in this build, making it incompatible with Gradle 5.0.
Use '--warning-mode all' to show the individual deprecation warnings.
See https://docs.gradle.org/4.10.3/userguide/command_line_interface.html#sec:command_line_warnings

BUILD SUCCESSFUL in 4s
3 actionable tasks: 3 executed
~/git/piv-conformance/tools/85b-swing-gui ~/git/piv-conformance
~/git/piv-conformance/cardlib ~/git/piv-conformance/tools/85b-swing-gui

> Configure project :
target java version: 1.8
source java version: 1.8
Runtime dependencies:

BUILD SUCCESSFUL in 0s
6 actionable tasks: 6 up-to-date
~/git/piv-conformance/tools/85b-swing-gui
~/git/piv-conformance/conformancelib ~/git/piv-conformance/tools/85b-swing-gui

BUILD SUCCESSFUL in 0s
6 actionable tasks: 4 executed, 2 up-to-date
~/git/piv-conformance/tools/85b-swing-gui

BUILD SUCCESSFUL in 0s
1 actionable task: 1 up-to-date

BUILD SUCCESSFUL in 0s
3 actionable tasks: 3 executed

Deprecated Gradle features were used in this build, making it incompatible with Gradle 5.0.
Use '--warning-mode all' to show the individual deprecation warnings.
See https://docs.gradle.org/4.10.3/userguide/command_line_interface.html#sec:command_line_warnings

BUILD SUCCESSFUL in 3s
3 actionable tasks: 3 executed
```
	
- Now, you tell Eclipse to import the Gradle configuration.
- In this order: `cardlib`, then `85b-swing-gui`, select the project from the explorer, right-click and select *Gradle* ->  *Refresh Gradle project*. You'll see the red decorators go away.
- For `conformancelib`, right-click and select *Configure -> Add Gradle Nature*.
- Now, right-click on the `conformancelib` project and you'll find the *Gradle* option. Take it.
- Now, all red decorators will be gone, and the project has already been built.
- The executable `.jar` file is in `./conformancelib/build/libs/conformancelib-all.jar`.  It's executable in any environment except perhaps your phone or watch.
- More importantly, you can start to play with the code.
- First, from a separate window, copy the file, `85b_test_definitions_PIV_ICAM_Test_Cards.db`, from the `./docs/coverage-testing` to the `./tools/85b-swing-gui` directory.
- Select the Debug configuration drop down and add a new Debug configuration.
- Call it `GuiRunnerApplication`.
- Select the `class gov.gsa.pivconformancegui.GuiRunnerApplication` as the main class.
- Your choice whether to stop in main. 
- Select Arguments.  Enter `--config 85b_test_definitions_PIV_ICAM_Test_Cards.db`.
- Apply and start debugging.

This is all how it is supposed to work, although there are currently some hiccups with getting Eclipse to see the `conformancelib` project.
