"""
Database initalize function. Makes models avaliable at higher levels
"""

from .models import (
    ScopesModel,
    UserModel,
    UserScopeModel,
    CertModel,
    ClientGrantMap,
    ClientModel,
    ClientRedirects,
    ClientScopeMap,
)
