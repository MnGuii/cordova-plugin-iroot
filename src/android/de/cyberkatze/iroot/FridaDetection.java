package de.cyberkatze.iroot;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

public class FridaDetection {
    
    private static final String TAG = "FridaDetection";
    
    // Portas padrão do Frida
    private static final int[] FRIDA_PORTS = {27042, 27043, 27044, 27045, 27046};
    
    // Bibliotecas relacionadas ao Frida
    private static final String[] FRIDA_LIBS = {
        "frida-agent",
        "frida-gadget", 
        "frida-helper",
        "frida-server",
        "re.frida.Gadget",
        "linjector"
    };
    
    // Processos relacionados ao Frida
    private static final String[] FRIDA_PROCESSES = {
        "frida-server",
        "frida-agent",
        "frida-gadget",
        "frida-helper",
        "frida",
        "re.frida.server",
        "linjector"
    };
    
    // Threads criadas pelo Frida
    private static final String[] FRIDA_THREADS = {
        "frida-agent-main",
        "frida-agent-pool",
        "frida-helper-backend",
        "frida-js-loop",
        "pool-frida"
    };

    /**
     * Verifica se o Frida está presente no sistema
     */
    public static boolean isFridaPresent(Context context) {
        return checkFridaPorts() || 
               checkFridaLibraries() || 
               checkFridaProcesses() ||
               checkFridaThreads() ||
               checkFridaFiles() ||
               checkDebuggerConnected() ||
               checkJavaDebugging() ||
               checkFridaMemoryPatterns();
    }
    
    /**
     * Verifica portas abertas pelo Frida
     */
    private static boolean checkFridaPorts() {
        try {
            File netFile = new File("/proc/net/tcp");
            if (!netFile.exists()) return false;
            
            BufferedReader reader = new BufferedReader(new FileReader(netFile));
            String line;
            
            while ((line = reader.readLine()) != null) {
                for (int port : FRIDA_PORTS) {
                    String hexPort = String.format("%04X", port);
                    if (line.contains(":" + hexPort)) {
                        reader.close();
                        return true;
                    }
                }
            }
            reader.close();
        } catch (Exception e) {
            // Ignorar erros
        }
        return false;
    }
    
    /**
     * Verifica bibliotecas carregadas relacionadas ao Frida
     */
    private static boolean checkFridaLibraries() {
        try {
            File mapsFile = new File("/proc/self/maps");
            if (!mapsFile.exists()) return false;
            
            BufferedReader reader = new BufferedReader(new FileReader(mapsFile));
            String line;
            
            while ((line = reader.readLine()) != null) {
                for (String lib : FRIDA_LIBS) {
                    if (line.toLowerCase().contains(lib.toLowerCase())) {
                        reader.close();
                        return true;
                    }
                }
            }
            reader.close();
        } catch (Exception e) {
            // Ignorar erros
        }
        return false;
    }
    
    /**
     * Verifica processos relacionados ao Frida
     */
    private static boolean checkFridaProcesses() {
        try {
            File statusFile = new File("/proc/self/status");
            if (!statusFile.exists()) return false;
            
            BufferedReader reader = new BufferedReader(new FileReader(statusFile));
            String line;
            
            while ((line = reader.readLine()) != null) {
                for (String process : FRIDA_PROCESSES) {
                    if (line.toLowerCase().contains(process.toLowerCase())) {
                        reader.close();
                        return true;
                    }
                }
            }
            reader.close();
        } catch (Exception e) {
            // Ignorar erros
        }
        return false;
    }
    
    /**
     * Verifica threads criadas pelo Frida
     */
    private static boolean checkFridaThreads() {
        try {
            File taskDir = new File("/proc/self/task");
            if (!taskDir.exists()) return false;
            
            File[] tasks = taskDir.listFiles();
            if (tasks == null) return false;
            
            for (File task : tasks) {
                File commFile = new File(task, "comm");
                if (commFile.exists()) {
                    try {
                        BufferedReader reader = new BufferedReader(new FileReader(commFile));
                        String threadName = reader.readLine();
                        reader.close();
                        
                        if (threadName != null) {
                            for (String fridaThread : FRIDA_THREADS) {
                                if (threadName.toLowerCase().contains(fridaThread.toLowerCase())) {
                                    return true;
                                }
                            }
                        }
                    } catch (Exception e) {
                        // Continuar
                    }
                }
            }
        } catch (Exception e) {
            // Ignorar erros
        }
        return false;
    }
    
    /**
     * Verifica arquivos específicos do Frida
     */
    private static boolean checkFridaFiles() {
        String[] fridaFiles = {
            "/data/local/tmp/frida-server",
            "/sdcard/frida-server",
            "/system/bin/frida-server",
            "/system/xbin/frida-server",
            "/data/local/tmp/re.frida.server",
            "/dev/socket/frida"
        };
        
        for (String file : fridaFiles) {
            if (new File(file).exists()) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Verifica se um debugger está conectado
     */
    private static boolean checkDebuggerConnected() {
        return android.os.Debug.isDebuggerConnected();
    }
    
    /**
     * Verifica debugging Java
     */
    private static boolean checkJavaDebugging() {
        try {
            // Verifica se está sendo executado em modo debug
            return (android.os.Debug.waitingForDebugger() || 
                    java.lang.management.ManagementFactory.getRuntimeMXBean()
                        .getInputArguments().toString().contains("jdwp"));
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Verifica padrões de memória específicos do Frida
     */
    private static boolean checkFridaMemoryPatterns() {
        try {
            // Verifica exceções específicas que o Frida pode gerar
            StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
            for (StackTraceElement element : stackTrace) {
                String className = element.getClassName();
                if (className.contains("frida") || 
                    className.contains("Frida") ||
                    className.contains("com.android.internal.os.ZygoteInit") && 
                    element.getMethodName().contains("nativeZygoteInit")) {
                    return true;
                }
            }
        } catch (Exception e) {
            // Ignorar
        }
        return false;
    }
    
    /**
     * Método adicional para verificar integridade da aplicação
     */
    public static boolean checkApplicationIntegrity(Context context) {
        try {
            // Verifica se o APK foi modificado
            ApplicationInfo appInfo = context.getApplicationInfo();
            File apkFile = new File(appInfo.sourceDir);
            
            // Verifica timestamp suspeito
            long lastModified = apkFile.lastModified();
            long currentTime = System.currentTimeMillis();
            
            // Se o APK foi modificado nas últimas 24 horas, pode ser suspeito
            if (currentTime - lastModified < 24 * 60 * 60 * 1000) {
                return false;
            }
            
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
