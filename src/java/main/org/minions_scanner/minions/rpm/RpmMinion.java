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

package org.minions_scanner.minions.rpm;

import com.sleepycat.je.Environment;
import com.sleepycat.je.EnvironmentConfig;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import io.grpc.stub.StreamObserver;
import java.io.IOException;
import org.minions_scanner.minions.MinionExecutor;
import org.minions_scanner.minions.AnalyzeFilesRequest;
import org.minions_scanner.minions.AnalyzeFilesResponse;
import org.minions_scanner.minions.ListInitialInterestsRequest;
import org.minions_scanner.minions.ListInitialInterestsResponse;
import org.minions_scanner.minions.MinionGrpc;
import java.io.File;
import java.util.logging.Logger;

/**
 * A Minion to analyze RPMs for security vulnerabilities. It will parse RPM databases and
 * use Vulners.com as a backend to identify vulnerable packages installed.
 */
public class RpmMinion extends MinionGrpc.MinionImplBase {
  private static final Logger logger = Logger.getLogger(RpmMinion.class.getName());

  @Override
  public void listInitialInterests(
      ListInitialInterestsRequest req, StreamObserver<ListInitialInterestsResponse> resObs) {
    ListInitialInterestsResponse reply = ListInitialInterestsResponse.newBuilder().build();
    resObs.onNext(reply);
    resObs.onCompleted();
  }

  @Override
  public void analyzeFiles(
      AnalyzeFilesRequest req, StreamObserver<AnalyzeFilesResponse> resObs) {
    // Parse the RPMs.

    
    
    AnalyzeFilesResponse reply = AnalyzeFilesResponse.newBuilder().build();
    resObs.onNext(reply);
    resObs.onCompleted();
  }

    /**
   * Main launches the server from the command line.
   */
  public static void main(String[] args) throws IOException, InterruptedException {
    String homeDirectory = "/tmp";
    System.out.println("Opening environment in: " + homeDirectory);
    EnvironmentConfig envConfig = new EnvironmentConfig();
    envConfig.setTransactional(true);
    Environment env = new Environment(new File(homeDirectory), envConfig);


    /*final MinionExecutor server = new MinionExecutor(new RpmMinion(), 50051);
    server.start();
    server.blockUntilShutdown();*/
  }

}
