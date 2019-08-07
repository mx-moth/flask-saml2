import sphinx_rtd_theme

import flask_saml2.version

project = 'Flask SAML2 IdP and SP'
copyright = '2019, Tim Heap'
author = 'Tim Heap'

# The short X.Y version.
version = '{}.{}'.format(*flask_saml2.version.version_info[:2])
# The full version, including alpha/beta/rc tags.
release = flask_saml2.version.version_str

extensions = [
    'sphinx.ext.autodoc',
    'sphinx_autodoc_typehints',
    'sphinx.ext.intersphinx',
]

templates_path = ['_templates']
source_suffix = '.rst'

master_doc = 'index'

add_module_names = True
autodoc_member_order = 'bysource'

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
exclude_patterns = ['_build']

pygments_style = 'sphinx'


# -- Options for intersphinx extension ---------------------------------------

# Example configuration for intersphinx: refer to the Python standard library.
intersphinx_mapping = {
    "python": ("https://docs.python.org/3.7", None),
    "flask": ("https://flask.palletsprojects.com/en/1.1.x", None),
    "OpenSSL": ("https://www.pyopenssl.org/en/stable/", None),
}

nitpick_ignore = [
    ('py:class', 'typing.Tuple'),
]

# -- Options for HTML output ----------------------------------------------
html_theme = 'sphinx_rtd_theme'
html_theme_path = [sphinx_rtd_theme.get_html_theme_path()]
html_static_path = []
htmlhelp_basename = 'flask_saml2_doc'

# -- Options for LaTeX output ---------------------------------------------

latex_elements = {}
latex_documents = [
    (master_doc, 'flask_saml2.tex', 'Flask SAML2 Documentation', 'Tidetech', 'manual'),
]


# -- Options for manual page output ---------------------------------------

# One entry per manual page. List of tuples
# (source start file, name, description, authors, manual section).
man_pages = [
    (master_doc, 'flask_saml2', 'Flask SAML2 Documentation', [author], 1)
]


# -- Options for Texinfo output -------------------------------------------

# Grouping the document tree into Texinfo files. List of tuples
# (source start file, target name, title, author,
#  dir menu entry, description, category)
texinfo_documents = [
    (
        master_doc, 'flask_saml2', 'Flask SAML2 Documentation',
        author, 'flask_saml2', 'One line description of project.',
        'Miscellaneous'),
]
