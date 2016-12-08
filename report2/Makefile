ARTICLE=main
TEX=$(wildcard ./*.tex)

%.pdf: $(TEX)
	latexmk -pdf ${@:.pdf=.tex}

all: $(ARTICLE).pdf

close_pdf:
	close_window Preview $(ARTICLE).pdf

open: $(ARTICLE).pdf close_pdf
	open $<

open2: open
	preview_at_page 8

fresh: clean open

.PHONY: clean
clean:
	latexmk -c
	rm -f *.pdf *.snm *.bbl

