ARTICLE=main

%.pdf: %.tex
	latexmk -pdf $^

all: *.tex $(ARTICLE).pdf

close_pdf:
	close_window Preview $(ARTICLE).pdf

open: $(ARTICLE).pdf close_pdf
	open $<

fresh: clean open

.PHONY: clean
clean:
	latexmk -c
	rm -f *.pdf *.snm *.bbl

