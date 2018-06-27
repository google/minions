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

import com.sleepycat.bind.tuple.IntegerBinding;
import com.sleepycat.bind.tuple.StringBinding;
import com.sleepycat.db.Cursor;
import com.sleepycat.db.DatabaseConfig;
import com.sleepycat.db.DatabaseEntry;
import com.sleepycat.db.DatabaseException;
import com.sleepycat.db.Environment;
import com.sleepycat.db.EnvironmentConfig;
import com.sleepycat.db.OperationStatus;
import com.sleepycat.db.Sequence;
import com.sleepycat.db.SequenceConfig;
import com.sleepycat.db.Database;
import com.sleepycat.db.DatabaseType;
import com.sleepycat.db.DatabaseConfig;
import com.sleepycat.db.Environment;
import com.sleepycat.db.EnvironmentConfig;
import com.sleepycat.db.LockMode;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import io.grpc.stub.StreamObserver;
import java.io.IOException;
import java.io.File;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.logging.Logger;  
import java.util.stream.Stream;
import org.minions_scanner.minions.MinionExecutor;
import org.minions_scanner.minions.AnalyzeFilesRequest;
import org.minions_scanner.minions.AnalyzeFilesResponse;
import org.minions_scanner.minions.ListInitialInterestsRequest;
import org.minions_scanner.minions.ListInitialInterestsResponse;
import org.minions_scanner.minions.MinionGrpc;

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
   	// First step: retrieve the OS version name and number.
    // TODO(paradoxengine): either get the /etc or the /usr/lib version from the request.
    Path path = Paths.get("/etc/os-release");
    try(Stream lines = Files.lines(path, Charset.forName("UTF-8"))) {
      OsReleaseParser.ParseResult osAndVer =
          OsReleaseParser.getOsAndVersion(lines);
    } catch (IOException e) {
      // TODO(paradoxengine): proper error management!
      throw new AssertionError(e);
    }

    AnalyzeFilesResponse reply = AnalyzeFilesResponse.newBuilder().build();
    resObs.onNext(reply);
    resObs.onCompleted();
  }

    /**
   * Main launches the server from the command line.
   */
  public static void main(String[] args) throws IOException, InterruptedException {
    /*DatabaseConfig dbConfig = new DatabaseConfig();
    dbConfig.setTransactional(true);
    dbConfig.setAllowCreate(true);
    dbConfig.setType(DatabaseType.HASH);
    String homeDirectory = "/tmp/foo";
    Environment env = new Environment(new File(homeDirectory), envConfig);
    Database db = env.openDatabase(null, "/tmp/foo/Packages", null, dbConfig);*/
    try {
      DatabaseConfig dbConfig = new DatabaseConfig();
      dbConfig.setTransactional(false);
      dbConfig.setAllowCreate(false);
      dbConfig.setType(DatabaseType.HASH);
      Database db = new Database("/tmp/Packages", null, dbConfig);
      
      Cursor cursor = db.openCursor(null, null);

      // Cursors need a pair of DatabaseEntry objects to operate. These hold
      // the key and data found at any given position in the database.
      DatabaseEntry foundKey = new DatabaseEntry();
      DatabaseEntry foundData = new DatabaseEntry();
      int found = 0;
      while (cursor.getNext(foundKey, foundData, LockMode.DEFAULT) ==
        OperationStatus.SUCCESS && found < 2) {
        found++;
        // getData() on the DatabaseEntry objects returns the byte array
        // held by that object. We use this to get a String value. If the
        // DatabaseEntry held a byte array representation of some other data
        // type (such as a complex object) then this operation would look 
        // considerably different.
        String keyString = new String(foundKey.getData());
        String dataString = new String(foundData.getData());
        System.out.println("Key | Data : " + keyString + " | " + 
                       dataString + "");
    }


      db.close();
    } catch (Exception e) {
      throw new AssertionError(e);
    }
    

    /*String homeDirectory = "/tmp/foo";
    EnvironmentConfig envConfig = new EnvironmentConfig();
    envConfig.setAllowCreate(true);
    Environment env = new Environment(new File(homeDirectory), envConfig);
    DatabaseConfig dbConfig = new DatabaseConfig();
    dbConfig.setAllowCreate(true);

    Database db = env.openDatabase(null, "Packages_2", dbConfig);
    System.out.println("Database opened: " + db.getDatabaseName());
    System.out.println("Count: " + db.count());

    DatabaseEntry key = new DatabaseEntry();
    DatabaseEntry data = new DatabaseEntry();

    IntegerBinding.intToEntry(1, key);
    StringBinding.stringToEntry("foo", data);
    
    // insert key/value pair to database
    db.put(null, key, data);

    System.out.println(db.count());
    db.close();
    env.close();
*/
    
/*    System.out.println("Opening environment in: " + homeDirectory);
    EnvironmentConfig envConfig = new EnvironmentConfig();
    envConfig.setTransactional(true);
    Environment env = new Environment(new File(homeDirectory), envConfig);*/


    /*final MinionExecutor server = new MinionExecutor(new RpmMinion(), 50051);
    server.start();
    server.blockUntilShutdown();*/
  }

}
