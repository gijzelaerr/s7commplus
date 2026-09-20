project = "s7commplus"
author = "Gijs Molenaar"
copyright = "2026, Gijs Molenaar"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
]

autodoc_typehints = "description"
autodoc_member_order = "bysource"
html_theme = "furo"
html_title = "s7commplus documentation"
html_theme_options = {
    "source_repository": "https://github.com/gijzelaerr/s7commplus/",
    "source_branch": "master",
    "source_directory": "docs/",
}
exclude_patterns = ["_build"]
