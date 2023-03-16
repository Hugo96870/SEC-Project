package test.java;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class MyTests {

    @Test1
    void testServerAndClient() throws IOException, InterruptedException {
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
                "-Dexec.args=\"localhost 8000\""
        );
        Process clientProcess = clientProcessBuilder.start();

        // Wait for the client process to finish
        int exitCode = clientProcess.waitFor();
        Assertions.assertEquals(0, exitCode, "Client process exited with non-zero exit code");

        // Read the client output and compare it with the expected input
        String expectedInput = "olaaaa";

        
        BufferedReader reader = new BufferedReader(new InputStreamReader(clientProcess.getInputStream()));
        String line;
        List<String> lines = new ArrayList<>();
        while ((line = reader.readLine()) != null) {
            lines.add(line);
        }
        reader.close();

        Assertions.assertEquals(expectedInput, lines.get(8));

        // Kill all the server processes
        for (Process serverProcess : serverProcesses) {
            serverProcess.destroy();
        }
    }

    @Test2
    void testServerAndClient() throws IOException, InterruptedException {
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
                "-Dexec.args=\"localhost 8000\""
        );
        Process clientProcess = clientProcessBuilder.start();

        // Wait for the client process to finish
        int exitCode = clientProcess.waitFor();
        Assertions.assertEquals(0, exitCode, "Client process exited with non-zero exit code");

        // Read the client output and compare it with the expected input
        String expectedInput = "olaaaa";

        
        BufferedReader reader = new BufferedReader(new InputStreamReader(clientProcess.getInputStream()));
        String line;
        List<String> lines = new ArrayList<>();
        while ((line = reader.readLine()) != null) {
            lines.add(line);
        }
        reader.close();

        Assertions.assertEquals(expectedInput, lines.get(8));

        // Kill all the server processes
        for (Process serverProcess : serverProcesses) {
            serverProcess.destroy();
        }
    }

    @Test2
    void testServerAndClient() throws IOException, InterruptedException {
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

        // Launch one client process
        ProcessBuilder clientProcessBuilder = new ProcessBuilder(
                "mvn",
                "compile",
                "exec:java",
                "-Dmainclass=pt.tecnico.SecureClient",
                "-Dexec.args=\"localhost 8000\""
        );
        Process clientProcess = clientProcessBuilder.start();

        // Wait for the client process to finish
        int exitCode = clientProcess.waitFor();
        Assertions.assertEquals(0, exitCode, "Client process exited with non-zero exit code");

        // Read the client output and compare it with the expected input
        String expectedInput = "olaaaa";

        
        BufferedReader reader = new BufferedReader(new InputStreamReader(clientProcess.getInputStream()));
        String line;
        List<String> lines = new ArrayList<>();
        while ((line = reader.readLine()) != null) {
            lines.add(line);
        }
        reader.close();

        Assertions.assertEquals(expectedInput, lines.get(8));

        // Kill all the server processes
        for (Process serverProcess : serverProcesses) {
            serverProcess.destroy();
        }
    }
}