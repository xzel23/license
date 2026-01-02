Licensing Concept
=================

Idea
----

The licensing scheme uses the following certificates and keys:

- Licensing Root Certificate and private key
- Licensing Quarterly Certificate and private key
- Build Certificate and private key

These are stored/distrubuted with the following components:

- **Developer Machine**

    - Licensing Root Certificate and private key
    - Licensing Quarterly Certificate and private key

- **Application**

    - Licensing Root Certificate without private key
    - Licensing Quarterly Certificate without private key
    - Build Certificate and private key

- **License Creation REST API**

    - Licensing Root Certificate without private key
    - Licensing Quarterly Certificate and private key

### License creation workflow

The application accepts licenses signed with either

- the Licensing Root Certificate (commercial licenses)
- the Licensing Quarterly License (trial licenses)

When the user asks to create a trial license using the application, the application sends 