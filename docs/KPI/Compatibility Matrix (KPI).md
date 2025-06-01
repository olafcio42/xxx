## Compatibility Matrix (KPI)

| Component               | 	PQC Support  | PQC Support	Version/Algorithm	       | Notes       |
|----------------------|---|-----------------|-----------------|
| OpenSSL  |  Yes | Kyber (OQS fork)    | Requires compilation with OQS  |
| HSM Model X       | No  | 	–   | Upgrade to Model Y required |
| Financial App A       | Partial  | 	ECDH + Kyber hybrid    | API update needed  |
| PKI (Active Directory)        | Yes  | 	–         | Migrate to hybrid certificates          |

	


    Yes: Full support for post-quantum algorithms.

    Partial: Limited functionality (e.g., specific use cases only).

    No: No support; corrective action required.