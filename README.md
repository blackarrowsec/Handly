# Handly
[![](https://img.shields.io/badge/Category-Lateral%20Movement-E5A505?style=flat-square)]() [![](https://img.shields.io/badge/Category-Privilege%20Escalation-E5A505?style=flat-square)]() [![](https://img.shields.io/badge/Language-.NET%20%2f%20Python-E5A505?style=flat-square)]()

Leverage leaked token handles to perform privilege escalation. This technique has been detailed in [this post](https://www.tarlogic.com/blog/token-handles-abuse-one-shell-to-handle-them-all/).

The technique is implemented for the following technologies:
* **IIS**: A simple ASPX webshell is provided that lists the available user tokens and allows to impersonate them to run an arbitrary executable present in the compromised host.
* **MSSQL**: A python script is provided that will load several C# assemblies, allowing to manipulate the user tokens available in the MSSQL's process memory. 

#

[![](https://img.shields.io/badge/www-blackarrow.net-E5A505?style=flat-square)](https://www.blackarrow.net) [![](https://img.shields.io/badge/twitter-@BlackArrowSec-00aced?style=flat-square&logo=twitter&logoColor=white)](https://twitter.com/BlackArrowSec) [![](https://img.shields.io/badge/linkedin-@BlackArrowSec-0084b4?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/company/blackarrowsec/)