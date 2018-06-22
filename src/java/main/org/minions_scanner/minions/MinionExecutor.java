package org.minions_scanner.minions;

//  Copyright 2018 Google LLC
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at

//        https://www.apache.org/licenses/LICENSE-2.0

//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//	limitations under the License.

import io.grpc.BindableService;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import io.grpc.stub.StreamObserver;
import java.io.IOException;
import java.util.logging.Logger;

/** A generic executor of minions, can be used to run any Minion. */
public class MinionExecutor {
  private static final Logger logger = Logger.getLogger(MinionExecutor.class.getName());

  /** Port to bind the server to. */
  final int port;

  /** Generic minion to execute. */
  final BindableService minion;

  private Server server;

  public MinionExecutor(BindableService minion, int port) {
    this.minion = minion;
    this.port = port;
  }

  /** Starts the minion. */
  public void start() throws IOException {
    server = ServerBuilder.forPort(port)
        .addService(minion)
        .build()
        .start();
    logger.info("Minion started, listening on " + port);
    Runtime.getRuntime().addShutdownHook(new Thread() {
      @Override
      public void run() {
        // Use stderr here since the logger may have been reset by its JVM shutdown hook.
        System.err.println("*** shutting down gRPC server since JVM is shutting down");
        MinionExecutor.this.stop();
        System.err.println("*** server shut down");
      }
    });
  }

  private void stop() {
    if (server != null) {
      server.shutdown();
    }
  }

  /**
   * Await termination on the main thread since the grpc library uses daemon threads.
   */
  public void blockUntilShutdown() throws InterruptedException {
    if (server != null) {
      server.awaitTermination();
    }
  }
}