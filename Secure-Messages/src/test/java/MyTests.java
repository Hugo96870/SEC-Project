/*package test.java;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.InputStream;
import java.util.Scanner;

public class MyTests {

    @Test
    void test1() throws IOException, InterruptedException {
        // Launch four server processes, each on a different port
        List<Process> serverProcesses = new ArrayList<>();
        
        for (int i = 0; i <= 2; i++) {
            ProcessBuilder serverProcessBuilder = new ProcessBuilder(
                    "mvn",
                    "compile",
                    "exec:java",
                    "-Dmainclass=pt.tecnico.SecureServer",
                    "-Dexec.args=\"1 8000 800" + i + " N\""
            );
            serverProcessBuilder.inheritIO(); // Redirects the process's output to the console
            Process serverProcess = serverProcessBuilder.start();
            serverProcesses.add(serverProcess);
        }
        ProcessBuilder serverProcessBuilderB = new ProcessBuilder(
            "mvn",
            "compile",
            "exec:java",
            "-Dmainclass=pt.tecnico.SecureServer",
            "-Dexec.args=\"1 8000 8003 B-PC\""
        );
        serverProcessBuilderB.inheritIO(); // Redirects the process's output to the console
        Process serverProcessB = serverProcessBuilderB.start();
        serverProcesses.add(serverProcessB);

        // Launch one client process
        ProcessBuilder clientProcessBuilder = new ProcessBuilder(
                "mvn",
                "compile",
                "exec:java",
                "-Dmainclass=pt.tecnico.SecureClient",
                "-Dexec.args=\"localhost 8000 olaaaa\""
        );
        clientProcessBuilder.redirectOutput(ProcessBuilder.Redirect.PIPE);
        Process clientProcess = clientProcessBuilder.start();

        // Get the exit value of the process
        int exitValue = clientProcess.waitFor();

        Assertions.assertEquals(0, exitValue);

        // Kill all the server processes
        for (Process serverProcess : serverProcesses) {
            serverProcess.destroy();
        }
    }

    @Test
    void test2() throws IOException, InterruptedException {
        // Launch four server processes, each on a different port
        List<Process> serverProcesses = new ArrayList<>();
        
        for (int i = 0; i <= 2; i++) {
            ProcessBuilder serverProcessBuilder = new ProcessBuilder(
                    "mvn",
                    "compile",
                    "exec:java",
                    "-Dmainclass=pt.tecnico.SecureServer",
                    "-Dexec.args=\"1 8000 800" + i + " N\""
            );
            serverProcessBuilder.inheritIO(); // Redirects the process's output to the console
            Process serverProcess = serverProcessBuilder.start();
            serverProcesses.add(serverProcess);
        }
        ProcessBuilder serverProcessBuilderB = new ProcessBuilder(
            "mvn",
            "compile",
            "exec:java",
            "-Dmainclass=pt.tecnico.SecureServer",
            "-Dexec.args=\"1 8000 8003 B-PP\""
        );
        serverProcessBuilderB.inheritIO(); // Redirects the process's output to the console
        Process serverProcessB = serverProcessBuilderB.start();
        serverProcesses.add(serverProcessB);

        // Launch one client process
        ProcessBuilder clientProcessBuilder = new ProcessBuilder(
                "mvn",
                "compile",
                "exec:java",
                "-Dmainclass=pt.tecnico.SecureClient",
                "-Dexec.args=\"localhost 8000 olaaaa\""
        );
        clientProcessBuilder.redirectOutput(ProcessBuilder.Redirect.PIPE);
        Process clientProcess = clientProcessBuilder.start();

        // Get the exit value of the process
        int exitValue = clientProcess.waitFor();

        Assertions.assertEquals(0, exitValue);

        // Kill all the server processes
        for (Process serverProcess : serverProcesses) {
            serverProcess.destroy();
        }
    }

    @Test
    void test3() throws IOException, InterruptedException {
        // Launch four server processes, each on a different port
        List<Process> serverProcesses = new ArrayList<>();
        
        for (int i = 0; i <= 2; i++) {
            ProcessBuilder serverProcessBuilder = new ProcessBuilder(
                    "mvn",
                    "compile",
                    "exec:java",
                    "-Dmainclass=pt.tecnico.SecureServer",
                    "-Dexec.args=\"1 8000 800" + i + " N\""
            );
            serverProcessBuilder.inheritIO(); // Redirects the process's output to the console
            Process serverProcess = serverProcessBuilder.start();
            serverProcesses.add(serverProcess);
        }
        ProcessBuilder serverProcessBuilderB = new ProcessBuilder(
            "mvn",
            "compile",
            "exec:java",
            "-Dmainclass=pt.tecnico.SecureServer",
            "-Dexec.args=\"1 8000 8003 B-PC-T\""
        );
        serverProcessBuilderB.inheritIO(); // Redirects the process's output to the console
        Process serverProcessB = serverProcessBuilderB.start();
        serverProcesses.add(serverProcessB);

        Thread.sleep(2000);

        // Launch one client process
        ProcessBuilder clientProcessBuilder = new ProcessBuilder(
                "mvn",
                "compile",
                "exec:java",
                "-Dmainclass=pt.tecnico.SecureClient",
                "-Dexec.args=\"localhost 8000 olaaaa\""
        );
        clientProcessBuilder.redirectOutput(ProcessBuilder.Redirect.PIPE);
        Process clientProcess = clientProcessBuilder.start();

        // Kill all the server processes
        for (Process serverProcess : serverProcesses) {
            serverProcess.destroy();
        }

        // Get the exit value of the process
        int exitValue = clientProcess.waitFor();

        System.out.println(exitValue);
        Assertions.assertEquals(0, exitValue);
    }
}*/