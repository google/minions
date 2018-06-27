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

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.common.collect.Lists;
import com.google.common.base.CharMatcher;
import com.google.common.base.Splitter;
import java.io.IOException;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.io.File;


class OsReleaseParser {

	/**
	 * Parses the os and version information from the stream of lines representing an os-release
	 * file and returns a structured {@link ParseResult}.
	 */
  public static ParseResult getOsAndVersion(Stream<String> lines) {
		Map<String, String> parsedFile = lines
			.filter(line -> !line.startsWith("#")) // Skip comments
			.filter(line -> !line.isEmpty()) // Skip empty lines
			.filter(line -> CharMatcher.is('=').countIn(line) == 1) // Exclude tricky lines
			.map(line -> parseLine(line)).collect(Collectors.toMap(e -> e.getKey(), e -> e.getValue()));
		return new ParseResult(parsedFile.get("NAME"), parsedFile.get("VERSION_ID"));
  }

	/** Parses a single line and returns KEY -> VALUE entry */
	private static Entry<String, String> parseLine(String line) {
		List<String> splitted = Lists.newArrayList(
				Splitter.on('=').trimResults(CharMatcher.anyOf(" '`\"")).split(line));
		String key = replaceExpansions(splitted.get(0));
		String value = replaceExpansions(splitted.get(1));
		return new SimpleImmutableEntry(key, value);
	}

	private static String replaceExpansions(String in) {
		return in.replace("\\\"", "\"").replace("\\\\", "\\")
				.replace("\\$", "$").replace("\\`", "`");
	}

	/** Data class holding the interesting results of parsing the OsRelease file. */
  public static class ParseResult {
		private final String os;
		private final String version;

    public ParseResult(String os, String version) {
      this.os = checkNotNull(os);
      this.version = checkNotNull(version);
    }

    public String version() {
      return version;
    }

    public String os() {
      return os;
    }
  }
}