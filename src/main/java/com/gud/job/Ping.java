package com.gud.job;

import java.io.*;
import java.net.*;
import java.nio.channels.*;
import java.util.*;
import java.util.regex.*;

public class Ping {
    static int DAYTIME_PORT = 13;
    static int port = DAYTIME_PORT;

    static class Target {
        InetSocketAddress address;
        SocketChannel channel;
        Exception failure;
        long connectStartTime;
        long connectFinishTime = 0;
        boolean shown = false;

        Target(String host) {
            try {
                address = new InetSocketAddress(InetAddress.getByName(host),
                        port);
            } catch (IOException ioException) {
                failure = ioException;
            }
        }

        void show() {
            String result;
            if (connectFinishTime != 0)
                result = Long.toString(connectFinishTime - connectStartTime) + "ms";
            else if (failure != null)
                result = failure.toString();
            else
                result = "Timed out";
            System.out.println(address + " : " + result);
            shown = true;
        }
    }

    static class Printer extends Thread {
        LinkedList pending = new LinkedList();

        Printer() {
            setName("Printer");
            setDaemon(true);
        }

        void add(Target t) {
            synchronized (pending) {
                pending.add(t);
                pending.notify();
            }
        }

        public void run() {
            try {
                for (; ; ) {
                    Target t = null;
                    synchronized (pending) {
                        while (pending.size() == 0)
                            pending.wait();
                        t = (Target) pending.removeFirst();
                    }
                    t.show();
                }
            } catch (InterruptedException x) {
                return;
            }
        }
    }

    static class Connector extends Thread {
        Selector sel;
        Printer printer;
        LinkedList pending = new LinkedList();

        Connector(Printer pr) throws IOException {
            printer = pr;
            sel = Selector.open();
            setName("Connector");
        }

        void add(Target t) {
            SocketChannel sc = null;
            try {
                sc = SocketChannel.open();
                sc.configureBlocking(false);
                boolean connected = sc.connect(t.address);
                t.channel = sc;
                t.connectStartTime = System.currentTimeMillis();
                if (connected) {
                    t.connectFinishTime = t.connectStartTime;
                    sc.close();
                    printer.add(t);
                } else {
                    synchronized (pending) {
                        pending.add(t);
                    }
                    sel.wakeup();
                }
            } catch (IOException x) {
                if (sc != null) {
                    try {
                        sc.close();
                    } catch (IOException xx) {
                    }
                }
                t.failure = x;
                printer.add(t);
            }
        }

        void processPendingTargets() throws IOException {
            synchronized (pending) {
                while (pending.size() > 0) {
                    Target t = (Target) pending.removeFirst();
                    try {
                        t.channel.register(sel, SelectionKey.OP_CONNECT, t);
                    } catch (IOException x) {
                        t.channel.close();
                        t.failure = x;
                        printer.add(t);
                    }
                }
            }
        }

        void processSelectedKeys() throws IOException {
            for (Iterator i = sel.selectedKeys().iterator(); i.hasNext(); ) {
                SelectionKey sk = (SelectionKey) i.next();
                i.remove();
                Target t = (Target) sk.attachment();
                SocketChannel sc = (SocketChannel) sk.channel();
                try {
                    if (sc.finishConnect()) {
                        sk.cancel();
                        t.connectFinishTime = System.currentTimeMillis();
                        sc.close();
                        printer.add(t);
                    }
                } catch (IOException x) {
                    sc.close();
                    t.failure = x;
                    printer.add(t);
                }
            }
        }

        volatile boolean shutdown = false;

        void shutdown() {
            shutdown = true;
            sel.wakeup();
        }

        public void run() {
            for (; ; ) {
                try {
                    int n = sel.select();
                    if (n > 0)
                        processSelectedKeys();
                    processPendingTargets();
                    if (shutdown) {
                        sel.close();
                        return;
                    }
                } catch (IOException x) {
                    x.printStackTrace();
                }
            }
        }
    }

    public static void main(String[] args) throws InterruptedException, IOException {
        //args = new String[] { "8888", "192.168.10.193" };
        args = new String[]{"80","www.baidu.com"};
        if (args.length < 1) {
            System.err.println("Usage: java Ping [port] host...");
            return;
        }
        int firstArg = 0;
        if (Pattern.matches("[0-9]+", args[0])) {
            port = Integer.parseInt(args[0]);
            firstArg = 1;
        }

        Printer printer = new Printer();
        printer.start();
        Connector connector = new Connector(printer);
        connector.start();

        LinkedList targets = new LinkedList();
//        for (int i = firstArg; i < args.length; i++) {
//            Target t = new Target(args[i]);
//            targets.add(t);
//            connector.add(t);
//        }

        for (int i = 0; i < 100; i++) {
            Target t = new Target(args[1]);
            targets.add(t);
            connector.add(t);
            Thread.sleep(2000);
        }


        connector.shutdown();
        connector.join();
        for (Iterator i = targets.iterator(); i.hasNext(); ) {
            Target t = (Target) i.next();
            if (!t.shown)
                t.show();
        }
    }


}
