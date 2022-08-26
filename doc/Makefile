.PHONY: default

# https://www.gnu.org/software/make/manual/html_node/Automatic-Variables.html

%.pdf: %.tex
	pdflatex $<

default:
	make ssl-notes.pdf
	make starting-apache.pdf
