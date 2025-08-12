Licensing Concept
=================

Idea
----

The licensing scheme uses the following certificates and keys:

- Licensing Root Certificate and private key
- Licensing Quarterly Certficate and private key
- Build Certificate and private key

These are stored/distrubuted with the following components:

- **Developer Machine**

    - Licensing Root Certificate and private key
    - Licensing Quarterly Certficate and private key

- **Application**

    - Licensing Root Certificate without private key
    - Licensing Quarterly Certficate without private key
    - Build Certificate and private key

- **License Creation REST API**

    - Licensing Root Certificate without private key
    - Licensing Quarterly Certficate and private key

### License creation workflow

The applicstion accepts licenses signed with either

- the Licensing Root Certificate (commercial licenses)
- the Licensing Quarterly License (trial licenses)

When the user asks to create a trial license using the application, the application sends 