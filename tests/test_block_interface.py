"""Tests for the block-interface parser.

The G2 fixtures are real EXPLORE blobs from a live S7-1200 G2 (FW V4.1) for an
optimized DB (``Data_block_1``) and a DB with a UDT member, exercising the
``DebugInfo_IntfDesc`` dict (Adler-32 ``0x66052b13``) and the RID -> SoftDataType
mapping. The instance-DB fixtures are real EXPLORE blobs from a live S7-1500
(FW V2.9) whose interface sits under a ``Values`` part: ``LGF_SinusCI_DB`` (an FB
instance), ``SLI_plcDB_rcvData_BRCV`` (a DB of a UDT) and ``IEC_Timer_S1_DB`` (an
instance of a library FB, which is referenced, not embedded). The test-program
fixtures pair each block's interface with its own ``LineComm`` stream, so comment
paths are checked on real bytes.
"""

import base64
import xml.etree.ElementTree as ET
import zlib

import pytest

from s7commplus.blob_decompressor import iter_preset_streams
from s7commplus.block_interface import (
    SOFTDATATYPE,
    BlockInterface,
    BlockInterfaceError,
    Member,
    block_interface_from_explore,
    parse_block_interface,
    resolve_id_path,
)

# Live S7-1200 G2 EXPLORE response for optimized DB "Data_block_1" (DB25), from
# the IdentES stream onward. Contains several preset-dict streams; the parser
# must skip IdentES (0x5814b03b) and target the interface dict (0x66052b13).
_DB_INTERFACE_BLOB = base64.b64decode(
    "eH1YFLA7rZXBToQwEIZfxezdUCosECtmdRc9oAfhBRqZYJPSGrZoeHtni2ukS0+7lx6+djqdmX+m"
    "p4mgNhGbwehXK5Gj73/ECSejJKTrNCZhlJCUuP18WCvDu0/7xprcrY4mYZTF6xRtktVVHXo49fAb"
    "D488PPbwxMPTZR5cfkCdqfLCVfkbSOB7eNSDMnlMWDADbKu/ldS8eRZ7o/sRR9T9NbllgcuZ1XPJ"
    "VTvwFkr4ApnjP7VAWc37FkzBOyHHvMLpRMgTZcEMs11VDOrdYBBcCjNOphRvXNzA43Mn00nH8aZp"
    "xGRY4suxKvAgFO9Hm7IDeoEOYylBteYDmzz7LeGf/n8AgprvX6OhQEAVAKOTcAAUAIZ3mAAAAnh9"
    "ZgUrE42Y224bOQyGX8XwPWGROi+aAE1TYHvVxWLRW0NHINhsncZOEezTl5qjPVM3vUlGE/ET+YtD"
    "Snm7Mrp1YbzckNuLDrTZ9T1o2Lv7u77icbL3O4TISRhez/PD9K+m75kUz/77A881pEhrb9WUA0Mz"
    "udneffry8Y8W/T423/a4Szln8p5AIQpQpAyEEA1QwWKKTsmjHepPOyuV1xPdbHtNWWbVTj3cNPpX"
    "TjT5h9ldrohX320I+q4h9zoiEk/idlUeb7ZfiGu66NNp+MoGuvK20QfxSYmpnbUoedLdh/v3+n2T"
    "8p9nrl2s/Sa98GchijEhGw8YkwelLYE30oJ1yQWSJsla2ejPh2NLhg3DVZZaqhK5oVkHqlQCV50C"
    "4ZRxwjprq9m2PTqzyRyFpGLA6aJBZV/ABRVA+sCvtYjV0tLG5GBTVR4cEq/jLPKTRJDCCMxBoo+4"
    "tJEuVO+KBJfQgLIhQ6iSQyJHhLy2dnZpQ6FaVF6ArDlyPK6AjzlweNkEgw6VXsXD0aAK0UJIxPFE"
    "ChxPSWC1z84a61Gs1qmOs0xKDcJGVhprBC+UZc29taiVMxRXGkShCvISxiPbRG1Za68guFyCSCkI"
    "HZY2WlcKaAyw4xyP4um+mgop8/uSpE5FLm1SirypMUCKVYIKQYEzPPSBXIq2RGlrZ7Mbs+d2rtzt"
    "KLFswknYLJzP4J2roGQUEKRLQNJirlkgJ9f2rLe3xByqbfsUNI7V5lgey4ndLHtuHPvwcjoMlXUu"
    "X13if26Mvtr6ztNzGo20p5fH4/7YTpn88/C0Tw/p8ToQByCKFVHO/p2e2tFlX5/Lt/1/h+bqEqgn"
    "oBmJ7NF3TqMVV43cf5/2f326X5LcSJI0ktQVkp5ID78kGTWS9IphJkb+JcNPcZkVw46MdPh6vCLQ"
    "rDi5keSuxOVG3jN3w0P4nyt2eVN3NQbZiulPsX7E8lWs3Rf4ahrexJox5QiXwPanEfj12Dv5cGTo"
    "KVyVEe2oI8nOTbmi4qzmM18XTr9BJTFq2roe84Y7y+Z40S6+X3acqb10nWXdRbpjYTO4hqGWWDy6"
    "BPFNam5cnTeHzWEwnQduHqCneSDPno2an705s9bnA3GGIjoz6TJtGph++d0gzW13/e22jcVvNXL6"
    "R0wvkRjmt9LHv6ZSuOvuxu8WV7LbHxNPf/Kjk3JAFAEAEJgAAAJ4fTxVQ2oDAAAAAAEAo6E/QBUA"
    "o7sMQBQAo70tQBQAo70lQBQAo5NaAAEAo5NlQBQAoqKiAAAAAA=="
)

# Live S7-1200 G2 EXPLORE response for DB "Data_block_1" after adding a member of
# a user UDT ("elettrovalvola"), from the interface stream onward. The blob
# bundles the DB interface and the UDT's own definition; the UDT member is
# expanded into Member.fields.
_DB_UDT_INTERFACE_BLOB = base64.b64decode(
    "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"
    "AKOTZUAUAKKiogAAAAA="
)

# Live S7-1500 (FW V2.9) EXPLORE response for instance DB "LGF_SinusCI_DB" (DB7),
# filtered to attribute 2544, from the zlib header onward. Its first <Part> is
# Kind="Values"; the members come from the embedded LGF_SinusCI FB.
_SINUS_INSTANCE_DB_INTERFACE_BLOB = base64.b64decode(
    "eH1mBSsTpVhbT+M4FP4rVefZ1PdLtVTiujvS7FYaqnngBTmJMyCxUAFF/Pw9ji91kgaWmQdEEud8"
    "Oba/7zvH/dgZ9dgY+xuy6lWg2SLUoLh3oT6EPT+en379cbH89uflDRjN7vns68356cJSy4hsJWq0"
    "ZYgTLlHVcIs4VqziuDKKGphE55vH85shxKIyurZWtMgJWiGuGUaVahWS1rmaNFRaSueZwT69bF9l"
    "ot0Mw1dAmIFNEvRi30oqq/AoWw8X8PL3M1gIrrkwgiiR6Rrr3i/nnHD+gYUT0Th9k+feXujxPJAB"
    "Y0Pj0PG8+MKBZg1yxMQgghEmG6yWVC05PlJCCKzF9YGeLwZgg6jcELJkeknxkZGcMEavC5f/vwHr"
    "v6+2Xmvl+1QgLCGpDcGQzpKRI6WpYOR62At8BN6tQadq/GYYxlTRU9irziPO3T3k2Zz5feraqaAC"
    "QiiwfQM9RbhnmEPEY+PugbcU32AcvCFaZlxxblTuRvzO47fTS3wptOJBVt/cw08vLi+MzRNUIlDS"
    "rN6ByVGphHXcIVuZFnEBW6GbmqHWSGalxZVUBoL+unv20p45TzdJW8U4sqw1iLfUgjbqCtW4bh3V"
    "QhMDOQKlF+lLq71n+yZiWH6JsVI3IDEnLUiMGowMYxYppSxvnHSNovOiqvtJRJ/1S0uTzXx92O5e"
    "hsaOPYmadXex6MWxFLfevRwIJJOBfP/B9TiOTsaJFHflC0A9DGSTgTIFbty/22EYnwzTKQwE6tvl"
    "UaqiHxo709nru1zMxOs4N2TbKlR///4ehwqYAdz1Q/e4lEfCxAxW3VniwfsMTMfTLp9qQ144vu/Z"
    "BP8yuw6aaEeLVEgLF+1SZ5JK/yfovhwsy4ieRUqupNWGIasbh7h1QH1RSdS24JSs4ZXg+EsDXuEU"
    "qQeCPKGUkxPDkqmdu21Q5EigeTphL/scylyAgwZ0ervGxb4hF2dd7GrXSxDYtdeOmAM+qoQVmq1J"
    "IEYTkphAylSDg9Pd4ygnJhOU5AlKHoZSWV3bW+garm7v2unEjIxonEwkZhIa1Mb79ekA6SRrjlCd"
    "ElOjlHAC8d3bKJtsFISnyXmwQlCZ9wRnxWQ6rP54nD2GNV7Ea79I6dpPMV2TiBtuTBExVtAikWev"
    "jkV3DC+lEZxvqA0ek5QCiptSWBbS6EV8XhtU1oTZ2g60waS40Fhe/J42ZN6nV9/gTbKGyKwMvT98"
    "QJnzFGIj8yUJ1T09PT5N777JKjEj1BExZa5a4Mwvu+chbHZ1ihMxPUMGsGIEm4va865KZ4SrD75A"
    "M23JxHK8R+S8d4mXEpe8LBjbTSXfUP45xvZb+FBCh8ylMStCMNQuwb1eMnV7IZ+nLieWNND2HGi/"
    "QMnD9oueE2XIOfskg3nJiu+2+dDbaUkKPcFgUaJ2S+WGPN47dDZ7yiagR32CT7tX3kmvvMuyawhr"
    "NVylSIqCOdEPP02PPk3WT3c/7+CYlE58kSeEJKJgIzBjhJXlP7z8Kwzh3BFal5scf4r8zR/oAkrx"
    "Ax184sdsCwYQ6p48opoRHewgDMCEbrsm9rXrl3AxxIqh8jkvntPiuSih5BfcR5Pl6FE5og98XJH3"
    "wFTImqZRLXujrB8Lo6QYlSPMuG4HKLPYd4rTT/qbsPoPObOuu6IAAAAA"
)

# Live S7-1500 (FW V2.9) EXPLORE response for DB "SLI_plcDB_rcvData_BRCV", declared
# of the UDT "BRCV_User", filtered to attribute 2544, from the zlib header onward.
# Its first <Part> is Kind="Values"; the members come from the embedded DataTypeSource.
_UDT_DB_INTERFACE_BLOB = base64.b64decode(
    "eH1mBSsTnVfbahsxEP0V43dldRndTOwHOy0JpASSkIe+LHvRloJbByctoV/fGWm19npzKQVjS0I6"
    "Gs3MOTP+WBndVBjHAVmNKtCsSDWoj12qDynmy/n66uHT4u76qnzcNhfrct/8JvvL9e3moeg86FYI"
    "x7RxLQOoA6t0i1+4zJ0S0FUdPibq53JeRig6WKLi7wtplHGhtUxLBwxakKySTWBKiVDZ1lRCwHzI"
    "YzJyELFjc8kcSod0DTI0pZVH4lQvxzltXFwaNEjifHO7QQ9qbbUVoNyQt30B/E+jk2JSdxdenuVy"
    "nrKAMoP6NCxzacnFtX43ejpf8krbhtZyKZng+LkXesHVQrkzLZX1Br6+0v19dGBQoX89cPPl7pHc"
    "PNqvGTdxP18AX0g481qC9HH/qC34CD26IBKcv3gR/bLBaEW5uAhbNLTdbFJQd23YYpJKXpLvYlVN"
    "+th7Gbwlf/S0kcCpYelrglRyaEso8njZZwP6AkTi13X4+Y1YRgy532NJQkrNml+odmCVbmQlGA/4"
    "avBdxSrrLGuc4XVX18Abg4cuvz8Rx2d4FyABlFItE513DDqvmfONZl1Xt6q23CiNtxajM0YLMAEC"
    "47WpGcjGsIqDYSpgzuHI152PZ4ps3eog+NSBnNZu3dayc6FhQemKgeXAXFtz1qHt0DbcG2PmRy0B"
    "PbwXaQqGhixSkVVhX4pehwex09HZN3Q0aTPlfzFG0RMU/iYMdnU9jp7gmIxDzeT+FGKdISjICcJM"
    "IGyGuEU93v04xXAZw0DGsBMMlzEuA8pQuQ7V8ymOyDh+eI6b4PiMgz1cKMXlnzetEWJ4kj+FMXwE"
    "o9+DgfwqyScwYmwNfw/H5ldJMcGRY3Pew5E0TDgy4vTd/+xpRN/diL4D2yPRT2m8Ot/NduSmBBgn"
    "8Zo84YehOt4j4TAxR2NvDmMhj4CESVBFbzSOiIH4MzCyiP/szotD3cor4+K8+g=="
)

# Live S7-1500 (FW V2.9) EXPLORE response for instance DB "IEC_Timer_S1_DB",
# filtered to attribute 2544, from the zlib header onward. Its Values part holds
# only a reference to the library FB IEC_TIMER, not its source.
_LIBRARY_INSTANCE_DB_INTERFACE_BLOB = base64.b64decode(
    "eH1mBSsTjZWxDoMgEIZfpWG/IoLnYcTB1sGhS5t0JQL6AH3/oShGYzu0K8PdR374v9/NSN/FeAyk"
    "ORjoxJOD1uySH1LmhrX9s6v67mLnAn/Zh7DXlsthLFShFfhAOSgSCBGVYJwylDhpP+Qq3mIpTsPs"
    "PqO/dXceic/EHVIQZUCQk/egFBKQoAGcxECq1Dpzjm3PeGbcOizRxn+zesqwf4btBNVCsBabYds5"
    "m7fwfQ1fzFx/CKF5"
)

# Live S7-1500 (FW V2.9) EXPLORE response for DB "Nested_DB_Three_Levels", filtered
# to attributes 2544 and 2546, from the zlib header onward. Its inline Structs nest
# three levels deep; each one's members sit in a Kind="Structure" part whose
# ParentId is the member's ID path (e.g. "52:52:52" for Branch1.Branch11.Branch111).
# It also holds an Array of Struct, a UDT inside a Struct and a member name full of
# special characters, and its member IDs do not follow declaration order.
_NESTED_STRUCT_DB_INTERFACE_BLOB = base64.b64decode(
    "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"
)

# Live S7-1500 (FW V2.9) EXPLORE responses of the program object for [2544, 2546], each cut
# to one block of a purpose-built test program: its interface stream and the LineComm stream
# that follows it, from the first zlib header onward. Each member's comment is the path it is
# declared at ("statStruct.inner.flag"); a constant's comment starts with "constant".

# User FB with every section, nested inline Structs, a UDT, arrays, a user-FB and a
# TON_TIME multi-instance, an IEC_TIMER and two constants.
_FB_COMMENTS_BLOB = base64.b64decode(
    "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"
)

# FC with every section, an Int return value and a constant.
_FC_COMMENTS_BLOB = base64.b64decode(
    "eH1mBSsTvVhdb9owFP0riD1b8bedqkUqgWp9GdJW9XVK4qBV2gAVqPj5u7Zj4yRECK3aQxVicuLr"
    "c88999LrzqiHxthNiO85ba7cg97kQN8+KRJkV55SRQi/FCuYCHj4e/EwZSRXhKtckJj1tn3Aq59f"
    "l3dPxU/oAXZhnwlVUyF5iUyjNOKYlkgLJRFZSya4WBujytZw7HDUnA70YepJBF5Z+5VTAj7l3C9D"
    "YFvT/H6YvlKwaOzV0RZNi+W5iv3IBu2WC7woFq1bHkDRFHh5eQcjAiIn9RFWzLpmhkC4WlGGeKkJ"
    "0mVjEFXrCuelolKUAPr6treZnUCaBDWGmbpEFWcScQ7YkugGVYprVq+l0A3Em83us7DT7Fyytof0"
    "3bdZm7rhhKEcU4I4UyXK4SVIS2LgT8iGldPE1G1y2zKzLNGgsufN7njo1zW2c6NZuQ9ZB8cCbnU8"
    "XACSUSA/b7ga4ugoTgbcS/Nn14exUZgKMKi34/umD+QJcOPCXjQ7W0dwv/tlFzpvsxqOr7NG0rpO"
    "LG3RGpBVf/BlwuDmw50NYmsHmEnUH8FtoeATnUPvzpcSNt36OXPrYrJyaHHwycfTiUuHsKAo7Gg3"
    "4FUMznnpdFEMtiRX3368jB4Pj58lS0IcPODqbDh+0EhBLLvZfRyA9n7k8apyw48XCny0FnuBIlso"
    "cImFE6eb1Nec4kOLCMZGgmsxzLnOqeC+uVmvuksRN9vWl5qvpSZU9oxmQZVaElKEn2hRgEnhX0i5"
    "iBX4tnkczRO5qrm4fao5PKa5M6WZ+1WS8umdYIxQmjOmFOZEJYR2ILczClZral2RT2I0WhMMhPM+"
    "pSRQer2MP49S55FjjBIIimKlWFeiq38glFWlYar6LImKKNFt0edTBz7Zf+TT9o5ROgXLRc60DSjS"
    "mQBuZ1NUNRfSsjAcONywApbshzdiGd8dkpuU/ke+zOWTgsIJHeUa8bFZHiD+xQV3iM3A54B3crBP"
    "w9qmYZ2zw2J2YnQ2O7cnJutdfaL8/yDiHoUuFmou5um5/SNwnex86/pwc4DdO3w12DE7N4Kw0h2D"
    "Z38Be71KX6OTckAUAQBymAAAAnh9PFVDasPuDjuIQyC2wgSV4P6A2mRqBBTCZgXYcCW75Py84pJE"
    "oHI353hnf7/gEBt9uGo7G32oYRimGuM3NTPPkThzTPCbk19a4kScQaYEHJTvTJw5ZvjNKUnNLXDB"
    "YZI+OJ3Z6GOPLQBRr5rsAKKhihMAApQTIACjk3AAFACGHpgAAAI="
)

# Program cycle OB with start information, a Temp and a constant. TIA writes its own
# comments on the start information.
_OB_COMMENTS_BLOB = base64.b64decode(
    "eH1mBSsTlVfJbtswEP0VwT0T4r4EtQHHTtBcGiA1cg20UKgBNxZqp/DndyguoiwXQS+WSZHD4Zs3"
    "b0afK6OeC+M0IL7mhFgNC73IAb99UBjQrrrkjJBymEoZTDksftksF1xqzajiNAU9VA+w/PT6cPd8"
    "/wYlwE2cSlzXkuCKIWaYQryuKNKNsahtdCdtxymlKuiN643s5UyXC48hwMrCq4EI+GKEm1Ub8Gug"
    "1dYeIK3aDfhEYO7Y2sNy8UpBtbEnTMijaM+QVKLcPfDlnmn8yIUJAnoGklOAavcbtAmwLZoPmAH/"
    "GyqsRB2DH94KieqqEohZrDuhSSeZgE3f9icX7AIiZxTwoiEG1dga2CENMo0liEsilWFaNg1gV072"
    "dJrbru0ooi2vEScAVGVFixiWXDdYVYKZYU8ZvVuNme9K0bWIK8WkxK2Cqskx4ry14IRUCKuad7TD"
    "SphukdUGx5GQrQ5tGsn69N5/nK/lgbr2s312u4r3Ybi1vWMrjPufLhwTY5KN1vbnfXV4cw1BSPAx"
    "i0KuUzJKIGXDpXNbPNpKSvhPQ3RmKHQbRWIGwYHV+LIGNlCx3oLvR98UHocLlfmY+CAEO/DPuzZ1"
    "MXq4s7/6a+hwBt30Zjpug0xw7dwMdTJFnXyGuogGXUY+f/+xuwZKRKCm4JTZtWaAuSSatxs0oZhy"
    "avU1NTwn3+IMy6boOebCIzE5dS25XjkYo/JHvSLhQEoZ1UIawXzNchp0l234bzX6ogWRNVHmpoQ4"
    "SYIYeIWGfhRa43M2yMVlzR+MfFRqkSXqLbIktsAnTP9iT9DP34hTCrwPGJ8E7JR7dMw9GnnORp6P"
    "jh2LRPEblB7DUg5fLD4m5dXTx8h/Y6QziNooLLTOL++XwLPoPTn/gEr5s+Or2YnlSIg4My1zq78z"
    "IRL3o5NyQBQBAIEhmAAAAnh9PFVDao2SvQ6CMBCAX+XCbNJBZaodcHKxibKbE0tschRCD5/fCshi"
    "bVgvd993f/E+1NTIZP0Gs2WO2ZRvQyimGOGZOjnLFgkqJIK2Bn5aD7qQYqlRUszIH/YuzT6U/WA2"
    "YGvoTYPuU/hARggLAnyhJbyTWWfap01V6zxjSNfF7ajP13IdNU9T2TTdxfiB+A9OjJ8lRfw+b9PH"
    "l5UAoqGJoAADv0cgAKKiAAAAAA=="
)

# UDT with an inline nested Struct.
_UDT_COMMENTS_BLOB = base64.b64decode(
    "eH1mBSsTlVZda9swFP0rxnvWrKsPyyqNoU1SVhgMStvXYtnyGIQ6LFvJz9+V9RElzhh7sn1tH13p"
    "nHPv/XdlbJaF8ZyQ9qwDFZXvQYE7l587X1/3UPKeJ45K7I65SKQPJVMD4MdPa1xCCSmVAsWSEEJH"
    "WZVv94+v2xscq96wMbjQoaKUK0lBkNpYSsSgGtJpLUk99lSA0ZyrLlQhNzHZ4y+2Kv3JutMOr2Z5"
    "0KOGOXqHqU2D3a3KV4Z1m3rJBCeFf4VWbm4KB1wL19lC8ZB1al9uQ/SoNozTDeVx0NrYvaODeV6+"
    "2vfv/rG9ff6JpQypKPrf6JLRWABlONHSWCIYl6Sra0qo4sYaBuPQNPjTlx8Hp40Cl2asYVpJQ2hv"
    "GREgJTG2HgnnupF6hH7oMQukrIortSfTuy50Wb91x5sazEiMph0RQvREjz0Q0Qg+dKNSWukyawu4"
    "yTY61Z2phKjUw97aIRgxqV3OZ/gNI8Gces4uB2ARAKsQGmUBARECW7rHALoA4RHkHYtQhoGEz5Rf"
    "1iwaQTmLoDCDhhGjOOTMTznzSSazQi4V0N5OxeRhq3AvmtO9z7wKq+Cd4wQviaPUinPTpfE9+Q2W"
    "foNzv+mQG1BNFYVagy/Uq/L+8cYD0v932icBlPVamauWgdwy7giSZeaH3DJ3YqvrB6XKTJ+BUNw4"
    "5hNqyF/EtrMfdneplOa62BaUumSmPLMTpXCiNMvwOnU+sZy8ah7Wc+b8OJ0wudJreFhv8137T/Ba"
    "7P0OP5A0Sf1yPsjm4PPTyzYLYvMJH7PP0ucWoRYZVSdZxch5B2j/APv4ykyjk3JAFAEAZJgAAAJ4"
    "fTxVQ2rD7g47iEMgtsIEleD+gNpkaggUwmYF2HAlu+KC1NQUG324CjsbfagBGCYZ4TcpNS8xKYdY"
    "s4zxm5WXWlxCtFFWhPwIMU0vJ7UsNQeHmfrgNGKjjz2kAf4nhNEAoqGJ/QALnlwgAKOTcAAUAIMf"
    "mAAAAg=="
)

# Instance DB of FB_Comments; its LineComm stream is empty.
_FB_COMMENTS_DB_BLOB = base64.b64decode(
    "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"
)

# Single-instance DB of the library timer TON_TIME; its LineComm stream is empty.
_TON_COMMENTS_DB_BLOB = base64.b64decode(
    "eH1mBSsTjZWxDoMgFEV/pWF/BRXhYcTB1sGhbdKYrgSk/kD/PymC0dgO7cpw3yUPzvlNRvwG434h"
    "zc5AB5octOwu+SHtXJO2f3TVcLuawPHZCS9zbqllufUj5lCWQgLn6MFOuQcuvVLSMvaUMtwiglMT"
    "EzP67mSG/tLdaWh8ROoE+kx6AcU0jiFDIGCGFlwhPHKpFHOOrM947rgyLLUN/2bxlCb/hG0Nqthg"
    "AZsm6zmZp9BtDI1mrj+E0LwBKQl0KqOTckAUAQAQmAAAAnh9PFVDagMAAAAAAQCioYoR4AChMSAA"
    "oqGKEf//oTEgAKKhijIAfJRXIACjk3AAFACFM5gAAAI="
)

# FB Frequency from the same program, not one of the test blocks: it keeps its four constants
# in a separate ConstantSection part, and its Root Constant header is empty.
_FREQUENCY_FB_BLOB = base64.b64decode(
    "eH1mBSsTpVjbbuM2EP2VwH3WijfxEmwMJI7dNbBZo6k37Zsh6tI+bO3UG2/Tv++QFCnqtl43QICY"
    "Emc0nDlzzkjnmVEOibFbEKc5Ta3sRkdygG9XFA6wy19jRAhhL4UOZgw2Py7gBxJECowUClVv5ONm"
    "trtbPy2vV8fq7xNE+G9a6kKXhcyTimmZMKJoolheJTynnAoteM2L4OXTAQ5HGvoxo1L1+kJuZjal"
    "GP6IDcjSF/HbLEbQq6Im7RxCdIi7r75Ax5ULCFdacXY5xYTBcgsK5daMGp+HsvpyM3siQPfIIa1p"
    "QFdMxJQI2mYSgF7vVrf3SylXfgq7r55NrYgr2sdq/4dZmrRvj8BzUKer4gQtBCDjudB5kqkaJaxC"
    "OpE1zhJOGWOYoEwLKEk6b5vaqEyfn3muM8ULleRa84QVuE60JirRtFaMA4QQrmcR7Zs4/DTydd4Z"
    "THptzz1E18vFbrt+WD76ahgWvJnBcAy+nOQ6eGbMm5gZZHuojexv9vYQnX3Z2L66thvTOKRoCcE2"
    "BGJrHoLbP59e+oyFTC3Kjf2Rduyot9ucXkYM8aQhax+4GdqRSbtw1F8NsxV9QzppGNK/rf567pux"
    "STPpzaBnzBw4CDXrmjYj19W377ZF6AEL/z7w507WzP7YD7iBVde09YtNC5t6NxE4LO5N78NxgCrb"
    "1zW3H7mAU9MF8C90hQdImPkiWA8h3XCEI2u8GsE4KHKgMM1liUXJE1oXRcIYl4nEwGCa8lIyoRTS"
    "+jrYXgMbv5NdFMdRhTEsJmALYK9lnoFxk2RCJIGHCoadCgNfr69ji4heCcc0YzlPCGZ1wkqZJbnk"
    "OFGKYyU0kzXiP0kJEWcy63EYBtLJVIZ7HIaGHBbS7jDXxTr26ax9VL2EIxmhz4q5akccDKj+Znsp"
    "wmWAD0YBeCHa+fvDFeSE9pGU+uBalKT2PStOvGOAfuaDsGGZMcSJUb6Q+Y7JpamvlZBUs0HqEREL"
    "gu7fmPpAiIWh6H7aA6+ZVNm8m3SOJj52GtiyMMkpD//s+47vvGNDGs4x/gHHyjuujsfDcTJa6VGC"
    "hzChA8JE3inw3svpa99r4EzFG69sGCo/Dz5frwZ8nsfswgwd/jdIeLtQ/DKIph2oOu2YhioMYFRQ"
    "FJNEx+RiqEpV1LnIRgYgAk/rIZiJW7lYDMhjZAD6LoKnhocBY7vxf7tZWdbt6xvvM4wdFbtVZgNA"
    "Tk4k//fpVv7c8+kPPJ/H2A3Vgh2TBEoyD2Pj9GzHifgB5nTmvWOym4kM0WdnCDoIPjV47wg+7gi+"
    "vR9uOhz1EdR0C4q7SLYLe+awkPItPeXno6muwkpJgqiUNOqqntGlfSUEzomu9NiLBULonAT47OEz"
    "rSRCsR/Wn3arx+Uvn0dg5Cgwwo7g49gRoTkebn8/425oHDTEGu62m93HzW8j3GztqRrndsEGXj6s"
    "f/4w5YahiVOdQcjbRz/7gtQZJ7uoc59fA9gyP+cpeOcTjHMSgc3tvRRjeS0xrgiPMdJ89H3jp1Dn"
    "JfoUCo94unp2NYYUYxgvrXin/jrU4087zIa7JLqbuevoHWovGhVx2jG4ZVAdvGXNnSaokYKm7bTt"
    "r3TPM/8PVjr7Q6OTckAUAQBGmAAAAnh9PFVDasPuDjuIQyC2wgSV4P6A2mRqCBTCZgXYcCU7z7yC"
    "0hKFzDwFjyobfbg6Oxt9qDFAFjj4bPSxOwIAvRA2ogCioYoSJymUEiQAo5NwABQAihqYAAAC"
)

_ARRAY_OF_UDT = (
    '<BlockInterface><Part Kind="DBSource" Block="DB1"><Payload><Root>'
    '<Member Name="arr" Type=\'Array[0..1] of "Motor"\' RID="0x02010011" ID="60" LID="1" StdO="0" />'
    "</Root></Payload></Part></BlockInterface>"
)


def test_parse_block_interface_types():
    # <Member> types are RID references into the SoftDataType table; a RID
    # outside the 0x0200_00XX namespace is a complex type left as raw hex.
    xml = (
        "<BlockInterface><Part><Payload><Root>"
        '<Member ID="51" Name="flag" RID="0x02000001" StdO="0" LID="9" />'
        '<Member ID="53" Name="speed" RID="0x02000005" StdO="16" LID="12" />'
        '<Member ID="54" Name="gain" RID="0x02000008" StdO="32" LID="14" />'
        '<Member ID="60" Name="timer" RID="0x0300abcd" StdO="48" LID="20" />'
        "</Root></Payload></Part></BlockInterface>"
    )
    assert parse_block_interface(xml) == [
        Member("flag", "Bool", 9, 0, 0x02000001, id=51),
        Member("speed", "Int", 12, 16, 0x02000005, id=53),
        Member("gain", "Real", 14, 32, 0x02000008, id=54),
        Member("timer", "0x0300ABCD", 20, 48, 0x0300ABCD, id=60),
    ]


def test_softdatatype_names_confirmed_ids():
    """Pin the name of every SoftDataType id that was confirmed on hardware.

    The ids were confirmed by browsing blocks that declare each type on an S7-1500 (6ES7 512-1CK01, FW V2.9).
    New names use the PLC's spelling from the member's Type attribute, or TIA's type keyword when the member has none.
    A failure means an entry of ``SOFTDATATYPE`` was renamed or removed, which changes ``Member.data_type`` for users.
    """
    # Source: https://github.com/gijzelaerr/s7commplus/issues/170#issuecomment-6831952583
    confirmed_datatypes_s7_1500 = {
        0: "Void",
        1: "Bool",
        2: "Byte",
        3: "Char",
        4: "Word",
        5: "Int",
        6: "DWord",
        7: "DInt",
        8: "Real",
        9: "Date",
        10: "TimeOfDay",
        11: "Time",
        12: "S5Time",
        14: "DateAndTime",
        19: "String",
        20: "Pointer",
        22: "Any",
        23: "BlockFB",
        24: "BlockFC",
        28: "Counter",
        29: "Timer",
        30: "IEC_COUNTER",
        31: "IEC_TIMER",
        48: "LReal",
        49: "ULInt",
        50: "LInt",
        51: "LWord",
        52: "USInt",
        53: "UInt",
        54: "UDInt",
        55: "SInt",
        61: "WChar",
        62: "WString",
        63: "Variant",
        64: "LTime",
        65: "LTimeOfDay",
        66: "LDT",
        67: "DTL",
        68: "IEC_LTIMER",
        69: "IEC_SCOUNTER",
        70: "IEC_DCOUNTER",
        71: "IEC_LCOUNTER",
        72: "IEC_UCOUNTER",
        73: "IEC_USCOUNTER",
        74: "IEC_UDCOUNTER",
        75: "IEC_ULCOUNTER",
        96: "Remote",
        97: "ErrorStruct",
        98: "NREF",
        101: "CREF",
        128: "AOM_IDENT",
        129: "EVENT_ANY",
        130: "EVENT_ATT",
        134: "EVENT_HWINT",
        144: "HW_ANY",
        145: "HW_IOSYSTEM",
        146: "HW_DPMASTER",
        147: "HW_DEVICE",
        148: "HW_DPSLAVE",
        149: "HW_IO",
        150: "HW_MODULE",
        151: "HW_SUBMODULE",
        152: "HW_HSC",
        153: "HW_PWM",
        154: "HW_PTO",
        155: "HW_INTERFACE",
        156: "HW_IEPORT",
        160: "OB_ANY",
        161: "OB_DELAY",
        162: "OB_TOD",
        163: "OB_CYCLIC",
        164: "OB_ATT",
        168: "CONN_ANY",
        169: "CONN_PRG",
        170: "CONN_OUC",
        171: "CONN_R_ID",
        173: "PORT",
        174: "RTM",
        175: "PIP",
        192: "OB_PCYCLE",
        193: "OB_HWINT",
        195: "OB_DIAG",
        196: "OB_TIMEERROR",
        197: "OB_STARTUP",
        200: "OPC_UA_LocalizedTextEncodingMask",
        201: "OPC_UA_ByteStringActualLength",
        208: "DB_ANY",
        209: "DB_WWW",
        210: "DB_DYN",
    }
    assert {
        softdatatype: SOFTDATATYPE[softdatatype] for softdatatype in confirmed_datatypes_s7_1500
    } == confirmed_datatypes_s7_1500


def test_parse_block_interface_names_unknown_softdatatype_by_id():
    xml = '<BlockInterface><Part><Payload><Root><Member ID="1" Name="m" RID="0x0200004f" StdO="0" LID="1" /></Root></Payload></Part></BlockInterface>'
    assert parse_block_interface(xml) == [Member("m", "SoftType#79", 1, 0, 0x0200004F, id=1)]


def test_member_without_id_matches_no_path_segment():
    # regression: a missing ID defaults to 0, and segment "0" resolved to this member
    xml = (
        "<BlockInterface><Part><Payload><Root>"
        '<Member Name="flag" RID="0x02000001" StdO="0" LID="9" />'
        "</Root></Payload></Part></BlockInterface>"
    )
    members = parse_block_interface(xml)
    assert members == [Member("flag", "Bool", 9, 0, 0x02000001, id=0)]
    assert resolve_id_path(members, "0") is None


def test_parse_block_interface_fb_sections():
    # FB/OB interfaces are organized in sections; the section-header <Member>s
    # (Input/Static, no RID) must be skipped, real members tagged with their
    # section. Complex members carry a ready-made ``Type`` attribute (arrays),
    # scalar ones resolve from the RID.
    xml = (
        '<BlockInterface><Part Kind="BlockSource"><Payload><Root>'
        '<Member ID="2" Name="Input" SubPartIndex="0" StdO="0" />'
        '<Member ID="5" Name="Static" SubPartIndex="1" StdO="0" />'
        "</Root></Payload>"
        "<SubParts>"
        '<Part Kind="InputSection"><Payload><Member>'
        '<Member ID="51" Name="puls_start_stop" RID="0x02000001" StdO="0" LID="9" />'
        "</Member></Payload></Part>"
        '<Part Kind="StaticSection"><Payload><Member>'
        '<Member ID="61" Name="num_step" RID="0x02000005" StdO="0" LID="19" />'
        '<Member ID="62" Name="timers" RID="0x0201001F"'
        ' Type="Array[0..5] of IEC_TIMER" StdO="16" LID="20" />'
        '<Member ID="63" Name="echo" RID="0x02010001"'
        ' Type="Array[0..2] of Bool" StdO="784" LID="21" />'
        "</Member></Payload></Part>"
        "</SubParts></Part></BlockInterface>"
    )
    assert parse_block_interface(xml) == [
        Member("puls_start_stop", "Bool", 9, 0, 0x02000001, "Input", id=51),
        Member("num_step", "Int", 19, 0, 0x02000005, "Static", id=61),
        Member("timers", "Array[0..5] of IEC_TIMER", 20, 16, 0x0201001F, "Static", id=62),
        Member("echo", "Array[0..2] of Bool", 21, 784, 0x02010001, "Static", id=63),
    ]


def test_parse_block_interface_udt_member_expands_fields():
    # A UDT member carries a readable ``Type`` ("MyUdt", TIA quotes), a RID in
    # the UDT object namespace (0x91......) and a ``SubPartIndex`` pointing at the
    # UDT's definition embedded under <SubParts>. That definition is expanded
    # into Member.fields, not surfaced as top-level members.
    xml = (
        '<BlockInterface><Part Kind="DBSource"><Payload><Root>'
        '<Member ID="51" Name="flag" RID="0x02000001" StdO="0" LID="9" />'
        '<Member ID="52" Name="valve" RID="0x91000001" Type="&quot;MyUdt&quot;"'
        ' SubPartIndex="0" StdO="16" LID="10" />'
        "</Root></Payload>"
        '<SubParts><Part Kind="DataTypeSource"><Payload><Root>'
        '<Member ID="60" Name="open_cmd" RID="0x02000001" StdO="0" LID="1" />'
        '<Member ID="61" Name="level" RID="0x02000005" StdO="16" LID="2" />'
        "</Root></Payload></Part></SubParts>"
        "</Part></BlockInterface>"
    )
    assert parse_block_interface(xml) == [
        Member("flag", "Bool", 9, 0, 0x02000001, "", id=51),
        Member(
            "valve",
            '"MyUdt"',
            10,
            16,
            0x91000001,
            "",
            fields=[
                Member("open_cmd", "Bool", 1, 0, 0x02000001, "", id=60),
                Member("level", "Int", 2, 16, 0x02000005, "", id=61),
            ],
            id=52,
        ),
    ]


def test_block_interface_from_live_g2_db_with_udt():
    members = block_interface_from_explore(_DB_UDT_INTERFACE_BLOB)
    # 12 top-level members; the embedded UDT definition is not surfaced flat.
    assert len(members) == 12
    valve = members[-1]
    assert (valve.name, valve.data_type, valve.rid) == (
        "elettrovalvola_1",
        '"elettrovalvola"',
        0x91000001,
    )
    assert [(f.name, f.data_type) for f in valve.fields] == [
        ("fc_apertura", "Bool"),
        ("fc_chiusura", "Bool"),
        ("stato_ev", "Int"),
        ("allarme_ev", "Int"),
        ("cons_ev", "Bool"),
        ("perc_apertura", "Real"),
    ]


def test_block_interface_from_live_g2_db():
    members = block_interface_from_explore(_DB_INTERFACE_BLOB)
    got = [(m.name, m.data_type) for m in members]
    assert got == [
        ("selettore_man_auto", "Bool"),
        ("puls_start_stop_ciclo", "Bool"),
        ("setpoint_freq_motore", "Int"),
        ("kp_PID", "Real"),
        ("ki_PID", "Real"),
        ("kd_PID", "Real"),
        ("cons_motore", "Bool"),
        ("retroazione_motore", "Int"),
        ("temperatura_motore", "Int"),
        ("tensione_misurata", "Real"),
        ("corrente_misurata", "Real"),
    ]


def test_block_interface_from_live_s7_1500_instance_db():
    members = block_interface_from_explore(_SINUS_INSTANCE_DB_INTERFACE_BLOB)
    assert [(m.name, m.section, m.lid) for m in members] == [
        ("amplitude", "Input", 14),
        ("offset", "Input", 15),
        ("periode", "Input", 16),
        ("phaseShift", "Input", 41),
        ("callOB", "Input", 17),
        ("reset", "Input", 28),
        ("value", "Output", 18),
        ("error", "Output", 19),
        ("status", "Output", 32),
        ("subFunctionStatus", "Output", 21),
        ("statRad", "Static", 22),
        ("statCounter", "Static", 23),
    ]


def test_block_interface_from_live_s7_1500_udt_db():
    members = block_interface_from_explore(_UDT_DB_INTERFACE_BLOB)
    assert [(m.name, m.data_type, m.lid) for m in members] == [
        ("Counter_1", "Int", 14),
        ("Counter_10", "Int", 15),
        ("Timer", "Time", 16),
        ("Random", "Real", 17),
        ("Heart_Beat", "Bool", 18),
        ("Sine_1Hz", "Real", 19),
        ("Sine_5Hz", "Real", 20),
        ("Sine_10Hz", "Real", 21),
        ("Sine_50Hz", "Real", 22),
    ]


def test_block_interface_from_live_s7_1500_library_instance_db_is_empty():
    # The Values part only references the library FB, so there is no source to parse.
    assert block_interface_from_explore(_LIBRARY_INSTANCE_DB_INTERFACE_BLOB) == []


@pytest.mark.parametrize("blob", [_LIBRARY_INSTANCE_DB_INTERFACE_BLOB, _TON_COMMENTS_DB_BLOB])
def test_library_instance_db_references_the_timer_type(blob):
    # a library FB is not embedded as a BlockSource, so there is no source; the reference is the timer type
    interface = BlockInterface.from_explore(blob)
    assert (interface.members, interface.source, interface.references) == ([], None, frozenset({"IEC_TIMER"}))


def test_parse_block_interface_values_part_without_source_is_empty():
    assert parse_block_interface('<BlockInterface><Part Kind="Values"><Payload /></Part></BlockInterface>') == []
    assert parse_block_interface('<BlockInterface><Part Kind="Values"><Payload /><SubParts /></Part></BlockInterface>') == []


def test_parse_block_interface_rejects_deep_nesting():
    # A 400-part chain with one member per part used to exceed Python's recursion limit
    member = '<Member ID="1" LID="1" Name="m" RID="0x02000011" SubPartIndex="{0}"/>'
    parts = "".join(
        f'<Part Kind="Structure"><Payload><Member>{member.format(i + 1)}</Member></Payload></Part>' for i in range(400)
    )
    xml_text = (
        f'<BlockInterface><Part Kind="DBSource"><Payload><Root>{member.format(0)}</Root></Payload>'
        f"<SubParts>{parts}</SubParts></Part></BlockInterface>"
    )

    with pytest.raises(ValueError, match="nests deeper"):
        parse_block_interface(xml_text)


# k Structure parts, each with two members pointing at the next part, expand to 2**k - 1 members.
# 20 parts is the reviewer's reproducer (about a million members); 3 parts expand to exactly 7.
@pytest.mark.parametrize(
    ("k", "max_members", "rejected"),
    [(20, 100_000, True), (3, 7, False), (3, 6, True)],
)
def test_parse_block_interface_caps_exponential_expansion(k, max_members, rejected):
    parts = []
    for i in range(k):
        mem = (
            ""
            if i == k - 1
            else (
                f'<Member ID="1" LID="1" Name="a" RID="0x02000011" SubPartIndex="{i + 1}"/>'
                f'<Member ID="2" LID="2" Name="b" RID="0x02000011" SubPartIndex="{i + 1}"/>'
            )
        )
        parts.append(f'<Part Kind="Structure"><Payload><Member>{mem}</Member></Payload></Part>')
    top = '<Member ID="1" LID="1" Name="s" RID="0x02000011" SubPartIndex="0"/>'
    xml_text = (
        f'<BlockInterface><Part Kind="DBSource"><Payload><Root>{top}</Root></Payload>'
        f"<SubParts>{''.join(parts)}</SubParts></Part></BlockInterface>"
    )

    if rejected:
        with pytest.raises(ValueError, match="more than"):
            parse_block_interface(xml_text, max_members=max_members)
    else:
        parse_block_interface(xml_text, max_members=max_members)


def test_block_interface_from_live_s7_1500_nested_struct_db():
    # An inline Struct member points via `SubPartIndex` at a Kind="Structure" part
    # in the same <SubParts> list as its parent, also when the parent is itself a
    # Structure part.
    def leaf(name: str, offset: int = 0) -> Member:
        return Member(name, "Bool", 9, offset, 0x02000001, id=51)

    def branch(name: str, lid: int, offset: int, rid: int, member_id: int, fields: list[Member]) -> Member:
        return Member(name, "Struct", lid, offset, rid, fields=fields, id=member_id)

    assert block_interface_from_explore(_NESTED_STRUCT_DB_INTERFACE_BLOB) == [
        Member(
            "Array of struct",
            "Array[0..1] of Struct",
            20,
            0,
            0x9A080000,
            fields=[Member("Array of bool", "Array[0..1] of Bool", 16, 0, 0x02010001, id=51)],
            id=58,
        ),
        branch(
            "Special struct",
            22,
            32,
            0x92090000,
            59,
            [
                Member(
                    "UDT",
                    '"BRCV_User"',
                    14,
                    0,
                    0x9100000C,
                    fields=[
                        Member("Counter_1", "Int", 14, 0, 0x02000005, id=54),
                        Member("Counter_10", "Int", 15, 16, 0x02000005, id=55),
                        Member("Timer", "Time", 16, 32, 0x0200000B, id=56),
                        Member("Random", "Real", 17, 64, 0x02000008, id=57),
                        Member("Heart_Beat", "Bool", 18, 96, 0x02000001, id=58),
                        Member("Sine_1Hz", "Real", 19, 112, 0x02000008, id=59),
                        Member("Sine_5Hz", "Real", 20, 144, 0x02000008, id=60),
                        Member("Sine_10Hz", "Real", 21, 176, 0x02000008, id=61),
                        Member("Sine_50Hz", "Real", 22, 208, 0x02000008, id=62),
                    ],
                    id=51,
                ),
                # The PLC stores this name already mojibake'd (UTF-8 "¬ß" for "§" etc.); it is asserted as sent.
                Member("Special_!¬ß$%&/()=?`¬¥\\+~*'#_-:.,<>|@^¬∞‚Ç¨¬µ{[]}", "HW_IO", 18, 240, 0x02000095, id=52),
            ],
        ),
        leaf("Leaf1", 288),
        branch(
            "Branch1",
            11,
            304,
            0x92010000,
            52,
            [
                leaf("Leaf11"),
                branch(
                    "Branch11",
                    11,
                    16,
                    0x92040000,
                    52,
                    [leaf("Leaf111"), branch("Branch111", 11, 16, 0x92070000, 52, [leaf("Leaf1111")])],
                ),
                branch("Branch12", 12, 48, 0x92050000, 53, [leaf("Leaf121")]),
            ],
        ),
        branch(
            "Branch2",
            12,
            368,
            0x92020000,
            53,
            [
                leaf("Leaf21"),
                branch("Branch21", 11, 16, 0x92030000, 52, [leaf("Leaf211")]),
                branch("Branch22", 12, 32, 0x92060000, 53, [leaf("Leaf221")]),
            ],
        ),
    ]


@pytest.mark.parametrize(
    ("data_type", "element_type"),
    [
        ('"Array[1] of Thing"', "Array[1] of Thing"),
        ('Array[0..3] of "Array[1] of Thing"', "Array[1] of Thing"),
        ('Array[0.."N"] of Bool', "Bool"),
    ],
)
def test_element_type_strips_only_a_leading_array_prefix(data_type: str, element_type: str):
    # a UDT name may itself read like an array type
    assert Member("m", data_type, 0, 0, 0).element_type == element_type


def test_array_of_udt_member_names_its_udt():
    # the quoted element type of an array member is its element_type and a reference
    info = BlockInterface.from_xml(_ARRAY_OF_UDT)
    assert info.members[0].element_type == "Motor"
    assert info.references == {"Motor"}


# an 11-digit id exceeds the \d{1,10} segment pattern; an index list holds integers only
@pytest.mark.parametrize(
    "id_path", ["", "60:", "x", "60[0", "99", "60:99", "60:12345678901", "60[]", "60[x,y]", "60[0,]", "60[0]]"]
)
def test_resolve_id_path_rejects_malformed_or_unknown(id_path: str):
    assert resolve_id_path(BlockInterface.from_xml(_ARRAY_OF_UDT).members, id_path) is None


@pytest.mark.parametrize(
    ("id_path", "expected"),
    [("51[3]", None), ("60[0]", None), ("60[0,1,2]", None), ("60[0,1]", "grid[0,1]"), ("60", "grid"), ("51", "flag")],
)
def test_resolve_id_path_needs_one_index_per_array_dimension(id_path: str, expected: str | None):
    members = [
        Member("flag", "Bool", 1, 0, 0x02000001, id=51),
        Member("grid", "Array[0..1, 0..2] of Int", 2, 2, 0x02010005, id=60),
    ]
    assert resolve_id_path(members, id_path) == expected


def test_resolve_id_path_stops_at_a_type_that_is_not_embedded():
    # arr is typed with "Motor", but the interface carries no definition of it
    assert resolve_id_path(BlockInterface.from_xml(_ARRAY_OF_UDT).members, "60[0]:51") is None


def test_parse_block_interface_reads_members_nested_in_their_section_header():
    # regression: OB/FC/library FB members inside the Root header were dropped
    assert [(m.section, m.name) for m in block_interface_from_explore(_OB_COMMENTS_BLOB)] == [
        ("Input", "Initial_Call"),
        ("Input", "Remanence"),
        ("Temp", "tempResult"),
        ("Constant", "OB_CONST"),
    ]


def test_parse_block_interface_keeps_declaration_order_and_returns_constants():
    assert [(m.section, m.name) for m in block_interface_from_explore(_FB_COMMENTS_BLOB)] == [
        ("Input", "inBool"),
        ("Output", "outInt"),
        ("InOut", "ioReal"),
        ("Static", "statStruct"),
        ("Static", "statUdt"),
        ("Static", "statUdtArray"),
        ("Static", "statStructArray"),
        ("Static", "statIntArray"),
        ("Static", "instInner"),
        ("Static", "instTon"),
        ("Static", "statTimer"),
        ("Temp", "tempInt"),
        ("Constant", "CONST_LIMIT"),
        ("Constant", "CONST_DELAY"),
    ]


def test_parse_block_interface_returns_an_fc_return_after_its_parameters():
    # regression: Return is nested in its Root header, declared after the headers of the
    # section parts holding the parameters; reading nested headers first put it before Input
    assert [(m.section, m.name) for m in block_interface_from_explore(_FC_COMMENTS_BLOB)] == [
        ("Input", "inA"),
        ("Output", "outB"),
        ("InOut", "ioC"),
        ("Temp", "tempD"),
        ("Return", "Ret_Val"),
        ("Constant", "FC_CONST"),
    ]


def test_parse_block_interface_reads_a_section_part_once_when_two_headers_select_it():
    xml = (
        '<BlockInterface><Part Kind="BlockSource"><Payload><Root>'
        '<Member ID="2" Name="Input" SubPartIndex="0" StdO="0" />'
        '<Member ID="3" Name="Output" SubPartIndex="0" StdO="0" />'
        "</Root></Payload><SubParts>"
        '<Part Kind="InputSection"><Payload><Member>'
        '<Member ID="51" Name="in" RID="0x02000005" StdO="0" LID="9" />'
        "</Member></Payload></Part>"
        "</SubParts></Part></BlockInterface>"
    )
    assert parse_block_interface(xml) == [Member("in", "Int", 9, 0, 0x02000005, "Input", id=51)]


def test_parse_block_interface_reads_a_section_part_no_header_selects():
    # the Input header's SubPartIndex is out of range; its part is still read, after the declared sections
    xml = (
        '<BlockInterface><Part Kind="BlockSource"><Payload><Root>'
        '<Member ID="2" Name="Input" SubPartIndex="7" StdO="0" />'
        '<Member ID="5" Name="Static" SubPartIndex="1" StdO="0" />'
        "</Root></Payload><SubParts>"
        '<Part Kind="InputSection"><Payload><Member>'
        '<Member ID="51" Name="in" RID="0x02000005" StdO="0" LID="9" />'
        "</Member></Payload></Part>"
        '<Part Kind="StaticSection"><Payload><Member>'
        '<Member ID="61" Name="stat" RID="0x02000005" StdO="0" LID="19" />'
        "</Member></Payload></Part>"
        "</SubParts></Part></BlockInterface>"
    )
    assert [(m.section, m.name) for m in parse_block_interface(xml)] == [("Static", "stat"), ("Input", "in")]


def test_parse_block_interface_reads_a_constant_section_part():
    # Frequency keeps its four constants in a ConstantSection part, not in the Root header
    assert [(m.section, m.name) for m in block_interface_from_explore(_FREQUENCY_FB_BLOB)] == [
        ("Input", "frequency"),
        ("Output", "clock"),
        ("Output", "countdown"),
        ("Output", "error"),
        ("Output", "status"),
        ("Static", "instTofTimeOn"),
        ("Static", "instTofTimeOff"),
        ("Static", "statFrequencyMem"),
        ("Static", "statTimeBase"),
        ("Constant", "MIN_FREQU"),
        ("Constant", "MAX_FREQU"),
        ("Constant", "FREQU_TO_LOW"),
        ("Constant", "FREQU_TO_HIGH"),
    ]


def test_resolve_id_path_looks_up_a_tof_time_instance_by_its_referenced_type():
    # regression: instTofTimeOn is typed TOF_TIME, but references names its type IEC_TIMER
    interface = BlockInterface.from_explore(_FREQUENCY_FB_BLOB)
    timer = next(member for member in interface.members if member.name == "instTofTimeOn")
    assert (timer.element_type, timer.referenced_type) == ("TOF_TIME", "IEC_TIMER")
    assert "IEC_TIMER" in interface.references
    types = {"IEC_TIMER": [Member("PT", "Time", 0, 0, 0x0200000B, id=3)]}
    assert resolve_id_path(interface.members, "54:3", types=types) == "instTofTimeOn.PT"


def test_parse_block_interface_sets_referenced_type_only_for_a_part_with_a_block_and_no_kind():
    # an embedded UDT has a Kind, and a UDT the interface does not embed points at an empty <Part/>
    xml = (
        '<BlockInterface><Part Kind="DBSource"><Payload><Root>'
        '<Member ID="1" Name="embedded" Type=\'"Motor"\' RID="0x02000011" SubPartIndex="0" />'
        '<Member ID="2" Name="missing" Type=\'"Pump"\' RID="0x02000011" SubPartIndex="1" />'
        '<Member ID="3" Name="timer" Type="TON_TIME" RID="0x0200001F" SubPartIndex="2" />'
        "</Root></Payload><SubParts>"
        '<Part Kind="DataTypeSource" Block="Motor"><Payload><Root /></Payload></Part>'
        "<Part />"
        '<Part LibElement="00000000-0000-0000-0000-000000000000:IEC_TIMER:1.0.8" Block="IEC_TIMER" />'
        "</SubParts></Part></BlockInterface>"
    )
    assert [(m.name, m.referenced_type) for m in parse_block_interface(xml)] == [
        ("embedded", None),
        ("missing", None),
        ("timer", "IEC_TIMER"),
    ]


def test_resolve_id_path_does_not_take_a_section_header_id():
    # 2 is the OB's Input header, 63 its Initial_Call: the comment path is just "63"
    assert resolve_id_path(block_interface_from_explore(_OB_COMMENTS_BLOB), "2:63") is None


@pytest.mark.parametrize(
    "blob",
    [_FB_COMMENTS_BLOB, _FC_COMMENTS_BLOB, _OB_COMMENTS_BLOB, _UDT_COMMENTS_BLOB],
    ids=["fb", "fc", "ob", "udt"],
)
def test_live_line_comment_paths_have_no_section_prefix(blob: bytes):
    # paths carry no section prefix. TIA writes its own comments on an OB's start information.
    fixed = {"Initial call of this OB": "Initial_Call", "=True, if remanent data are available": "Remanence"}
    members = BlockInterface.from_explore(blob).members
    comments = next(stream for stream in iter_preset_streams(blob) if stream.preset.kind == "LineComm")
    resolved: dict[str, str | None] = {}
    expected: dict[str, str | None] = {}
    for comment in comments.xml.iter("Comment"):
        path, text = comment.get("Path", ""), next(comment.iter("DictEntry")).text or ""
        resolved[path] = resolve_id_path(members, path)
        expected[path] = fixed.get(text, text.removeprefix("constant "))
    assert resolved == expected
    assert len(expected) >= 4


def test_live_user_fb_instance_db_has_its_fb_as_source():
    interface = BlockInterface.from_explore(_FB_COMMENTS_DB_BLOB)
    assert interface.source == "FB_Comments"
    assert interface.references == frozenset({"FB_Inner", "IEC_TIMER", "UDT_Comments"})


def test_resolve_id_path_does_not_look_up_an_empty_struct_in_types():
    # an inline Struct is always embedded, so "Struct" in types must not supply its fields
    xml = (
        '<BlockInterface><Part Kind="DBSource"><Payload><Root>'
        '<Member ID="60" Name="s" RID="0x00000000" SubPartIndex="0" />'
        '</Root></Payload><SubParts><Part Kind="Structure"><Payload /></Part></SubParts></Part></BlockInterface>'
    )
    members = BlockInterface.from_xml(xml).members
    assert members[0].data_type == "Struct"
    assert resolve_id_path(members, "60:51", types={"Struct": [Member("wrong", "Int", 0, 0, 0, id=51)]}) is None


def test_resolve_id_path_looks_up_a_udt_named_struct():
    types = {"Struct": [Member("x", "Int", 1, 0, 0, id=7)]}
    assert resolve_id_path([Member("m", '"Struct"', 1, 0, 0, id=5)], "5:7", types=types) == "m.x"
    assert resolve_id_path([Member("a", 'Array[0..1] of "Struct"', 1, 0, 0, id=5)], "5[0]:7", types=types) == "a[0].x"


def test_instance_db_names_its_fb():
    # Live S7-1500 LGF_SinusCI_DB: the FB sits below the Values part
    assert BlockInterface.from_explore(_SINUS_INSTANCE_DB_INTERFACE_BLOB).source == "LGF_SinusCI"


def test_udt_db_has_no_source():
    # A DataTypeSource below Values is a DB of a UDT, not an instance
    assert BlockInterface.from_explore(_UDT_DB_INTERFACE_BLOB).source is None


def test_info_from_explore_without_stream_is_empty():
    assert BlockInterface.from_explore(b"no zlib stream here") == BlockInterface([], None, frozenset())


@pytest.mark.parametrize("caught", [BlockInterfaceError, ValueError, ET.ParseError])
def test_from_xml_rejects_malformed_xml(caught: type[Exception]):
    # older callers catch ElementTree's ParseError, newer ones ValueError
    with pytest.raises(caught, match="not well-formed"):
        BlockInterface.from_xml("not xml")
    with pytest.raises(caught, match="not well-formed"):
        parse_block_interface("not xml")


def test_from_xml_without_part_is_empty():
    assert BlockInterface.from_xml("<Other />") == BlockInterface([], None, frozenset())


def test_from_xml_values_part_with_empty_block_has_no_source():
    # an empty Block attribute must not become the source name ""
    xml = '<BlockInterface><Part Kind="Values"><SubParts><Part Kind="BlockSource" Block="" /></SubParts></Part></BlockInterface>'
    assert BlockInterface.from_xml(xml).source is None


def test_from_xml_references_skip_empty_names():
    xml = (
        '<BlockInterface><Part Kind="DBSource" Block=""><Payload><Root>'
        '<Member Name="a" RID="0x02010001" Type=\'Array[0..1] of "Motor"\' />'
        '</Root></Payload></Part><ExternalType /><ExternalType Name="Ext" /></BlockInterface>'
    )
    assert BlockInterface.from_xml(xml).references == {"Motor", "Ext"}


def test_from_explore_raises_on_corrupt_stream():
    # a DebugInfo IntfDesc header followed by an invalid deflate block,
    # which find_preset_stream selects and decompress_blob rejects
    payload = bytes.fromhex("787d 66052b13") + b"\xff" * 8
    with pytest.raises(ValueError, match="corrupt") as caught:
        BlockInterface.from_explore(payload)
    assert isinstance(caught.value.__cause__, zlib.error)


def test_from_xml_references_skip_array_bound_constants():
    xml = (
        '<BlockInterface><Part Kind="DBSource" Block="DB1"><Payload><Root>'
        '<Member Name="a" RID="0x02010011" Type=\'Array[1.."c_max"] of "Motor"\' />'
        "</Root></Payload></Part></BlockInterface>"
    )
    assert BlockInterface.from_xml(xml).references == {"Motor"}


def test_from_xml_references_leave_out_the_block_itself():
    # Synthetic: the captured DBs leave Block off their primary Part, but a UDT or FB explored on its own
    # may name itself there. Only the UDT its member is typed with is a reference.
    xml = (
        '<BlockInterface><Part Kind="DataTypeSource" Block="Motor"><Payload><Root>'
        '<Member ID="51" Name="valve" RID="0x02000005" Type=\'"Valve"\' />'
        "</Root></Payload></Part></BlockInterface>"
    )
    assert BlockInterface.from_xml(xml).references == {"Valve"}


@pytest.mark.parametrize(
    ("data_type", "expected"),
    [
        ("Int", "Int"),
        ("IEC_TIMER", "IEC_TIMER"),
        ('"Motor"', "Motor"),
        ("Array[0..5] of IEC_TIMER", "IEC_TIMER"),
        ('Array[1.."c_max"] of "Motor"', "Motor"),
        ('Array[0.."N"] of Bool', "Bool"),
    ],
)
def test_member_element_type(data_type: str, expected: str):
    # a UDT, a library type and an elementary type are all named
    assert Member("m", data_type, 0, 0, 0).element_type == expected


def test_resolve_id_path_follows_types_into_array_element_udt():
    members = BlockInterface.from_xml(_ARRAY_OF_UDT).members
    motor = [Member("speed", "Int", 1, 0, 0x02000005, id=51)]
    assert resolve_id_path(members, "60[0]:51", types={"Motor": motor}) == "arr[0].speed"


def test_resolve_id_path_follows_types_into_library_type():
    # IEC_TIMER is a library type, quoted nowhere, and is still found by its element_type
    timer = Member("t", "Array[0..5] of IEC_TIMER", 1, 0, 0x02010011, id=7)
    pt = [Member("PT", "Time", 1, 0, 0x0200000B, id=3)]
    assert resolve_id_path([timer], "7[2]:3", types={"IEC_TIMER": pt}) == "t[2].PT"
