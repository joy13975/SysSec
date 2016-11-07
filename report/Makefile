ARTICLE=main

SRCS=overview.tex task1_tech.tex task2_tech.tex task1_refl.tex task2_refl.tex

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

