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

import static com.google.common.truth.Truth.assertThat;

import java.util.ArrayList;
import java.util.List;
import org.junit.Test;

public class OsReleaseParserTest {

  @Test
  public void skipsEmptyAndCommentLines() {
    List<String> fakeFile = new ArrayList<>();
    fakeFile.add("");
    fakeFile.add("#NAME=SOMETHINGELSE");
    fakeFile.add("NAME=MyName");
    fakeFile.add("# NAME=SOMETHINGELSEENTIRELY");
    fakeFile.add("#NAME=YETSOMETHING");
    fakeFile.add("VERSION_ID=IRRELEVANT");
    fakeFile.add("");
    OsReleaseParser.ParseResult out = OsReleaseParser.getOsAndVersion(fakeFile.stream());
    assertThat(out.os()).isEqualTo("MyName");
  }
}