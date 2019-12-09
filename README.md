# Cypher Injection Scanner

## Description

This is a Burp Suite Extension that detects Cypher code injection in applications using Neo4j databases.

## Features

### Active Scanner

Attempts to detect Cypher injection by sending payloads that aim to perform requests to the Burp Collaborator Client.

### Passive Scanner

Alerts whens the application responds with descriptive errors.

## Build

<pre>./gradlew build</pre>