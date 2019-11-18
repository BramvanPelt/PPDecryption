WARNING: This repository has been updated at 18-11-2019 whith an additional signature verification method. This new signature method will be the new defacto standard starting from december 2020. If you have implemented this library before the update date, please download the sources again and recomplile. You should be able to replace the libary jars with no problems.

ABSTRACT
This repository contains two projects, the PP-Decrypt library and the PP-Decrypt example package. 
The goal of these project is to give an example of how the decryption of encrypted identifiers takes 
place in an polymorphic pseudonym environment. 

ABOUT POLYMORPHIC PSEUDONYMISATION
Polymorphic pseudonymisation is an encryption technology developed by Eric Verheul to ensure the 
privacy and security of users in an authentication system. This technology has been incorporated 
in the Dutch "EID" system. Polymorphic pseudonymisation is based on the El-Ghamal encryption system
and split proof evidence. For more information on the El-Ghamal crypto system, please see: ... .

For more information on Polymorphic pseudonymisation pease see: http://www.cs.ru.nl/E.Verheul/papers/PP2/PEKScheme.pdf

INSTALL
The library can be installed by compiling the code and adding the resulting JAR file to the JAVA_HOME build path.
The example can be runned from the commandline by copiling the code and executing the following command:

Java "example.jar"

CONTRIBUTE
You can contribute to this project by forking the repository at: ... and make your contribution to the fork,
then open a pull request to initiate a discussion around the contribution.

LICENCE
This software is free software: you can redistribute it and/or modify it under the terms of the EUPL 1.2
licence. 

The software in this repository meets the requirement to be REUSE compliant, meaning its licence and copyright
is expressed in such a way so that it can be read by both humans and computers alike

For more information, see https://reuse.software

ACTKNOWLEDGEMENTS
Special thanks to:

- Logius (For publication of documentation)
- Martijn Kooij
- Eric Verheul
- Ewald Wasscher

For making this repository possible.

CONTACT:
Administration of the repo can be contacted via: bram.vanpelt@kpn.com

AFFILIATED PROJECTS:

https://github.com/MartijnKooij/PolymorphicPseudonymisation (Dotnet implementation of this library)

https://github.com/ewasscher/pp-decrypt-core (Maven rapackaged version of this project)
