%% Noroff university College Thesis Style file
%% Inspired by   RU Computer Science Class  2010
%% (c) Barry Irwin 2021

%% CHANGELOG - see CHANGLE log file

%% TODO
%    Fine-tuning margins to deal with two sided printing (potentially)
%    Citation template



%---------------------------------------------------------------------------------
\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{nucthesis}[2021/03/09 Noroff University College Thesis Class]

\def\currversion{August 2, 2021} 

\newcommand{\Degree}{Bachelor in Cyber Security} %% default
\DeclareOption{CSE}{\renewcommand{\Degree}{Bachelor in Cyber Security}}
\DeclareOption{DFO}{\renewcommand{\Degree}{Bachelor in Digital Forensics}} 
\DeclareOption{ADS}{\renewcommand{\Degree}{Bachelor in Applied Data Science}}

%% Stop fonts being too small.
% \DeclareOption{10pt}{
%   \ClassWarningNoLine{CSE}{%
%     The `10pt' option is not allowed in the `nucthesis' class}
%   \OptionNotUsed
% }


\DeclareOption*{\PassOptionsToClass{\CurrentOption}{report}}
\ProcessOptions\relax
%\ProcessOptions
% we are based off the core report class so pass this through  *again*
%
\if@twoside%
    \LoadClass[10pt, a4paper, twoside, openright]{report} %% twoside=true
\else%
    \LoadClass[10pt, a4paper, oneside]{report} %% twoside=false
\fi%

% Ensure URL is loaded first
\PassOptionsToPackage{hyphens}{url} % make sure to split on hyphens for urls
\RequirePackage[hyphens]{url} % make sure to split on hyphens for urls
\RequirePackage{hyperref} % There are lots of options that can be added here. RTFM - https://ctan.org/pkg/hyperref?lang=en
\RequirePackage{doi} % hyperlinks DOI's in refs
% \RequirePackage{helvet} %helvetica
% \renewcommand{\familydefault}{\sfdefault}
%Font is handled in main.tex

\RequirePackage[utf8]{inputenc}
\RequirePackage{graphicx}
%page Setup - DO NOT ALTER
%\RequirePackage{geometry}
%    \if@twoside% twoside=true
%        \geometry{left=25mm,right=25mm,bindingoffset=10mm, top=20mm,bottom=35mm} %% 
%    \else% twoside=false
%        \geometry{left=25mm,right=25mm,bindingoffset=0mm, top=20mm,bottom=35mm} %% 
%    \fi%

%% packages dealing with layout
\RequirePackage[a4paper]{geometry}
\RequirePackage[dvipsnames]{xcolor} 
\RequirePackage{fancybox}
\RequirePackage{fancyhdr}
\RequirePackage{verbatim}
\RequirePackage[parfill]{parskip} %Sets full justification and paragraph spacing} 

%% some other useful components
\RequirePackage{calc}
\RequirePackage{ifthen}
\RequirePackage{setspace}
%\RequirePackage{acmart} %% required for ACM CCS - see https://www.acm.org/publications/class-2012

\RequirePackage[english]{babel} % set UK spelling.
\RequirePackage{minted}

\RequirePackage[autostyle]{csquotes}
\MakeOuterQuote{"} %prevents backwards quote symbols

\DeclareOption*{\PassOptionsToClass{\CurrentOption}{report}}
\ProcessOptions\relax

\usepackage[style=authoryear,backend=biber]{biblatex}
\DeclareLanguageMapping{british}{british-apa}
\addbibresource{ref.bib}

\usepackage[parfill]{parskip} %Sets full justification and paragraph spacing


%% define Hyperref  details here
\hypersetup{
	colorlinks=true, %set true if you want coloured links
	linktoc=all,     %set to all if you want both sections and subsections linked
	linkcolor=black,  %choose some colour if you want links to stand out	
	citecolor=black,
%	citecolor=blue,
    filecolor=blue,      
    urlcolor=blue, % URLs via \url and \hyperref
}

\newcommand{\MYhref}[3][black]{\href{#2}{\color{#1}{#3}}}%

\newcommand{\NUCLogo}{images/nuc.png}


\newcommand\frontmatter{%
    \cleardoublepage
  %\@mainmatterfalse
  \pagenumbering{roman}}

\newcommand\mainmatter{%
    \cleardoublepage
 % \@mainmattertrue
  \pagenumbering{arabic}}

\newcommand\backmatter{%
  \if@openright
    \cleardoublepage
  \else
    \clearpage
  \fi
 % \@mainmatterfalse
   }


%disabled till we have alternate types
\newcommand{\DegType}{partial fulfilment}
%\newcommand{\degree}[1]{\renewcommand{\Degree}{#1}}
%\newcommand{\partdegree}[1]{\renewcommand{\Degree}{#1} \renewcommand{\DegType}{partial fulfilment}}
%\newcommand{\fulldegree}[1]{\renewcommand{\Degree}{#1} \renewcommand{\DegType}{partial fulfilment}}
\newcommand{\TitleBox}{false}
\newcommand{\titlebox}[1]{\renewcommand{\TitleBox}{#1}}
\newcommand{\Logo}{true}
% default is on - to disable in tex \renewcommand{\Logo}{false}
\newcommand{\logo}[1]{\renewcommand{\Logo}{#1}}

\newcommand{\SetMargins}[3]{
	\setlength{\hoffset}{-25mm + (#1 / 2)}
	\setlength{\voffset}{-25mm}
	\setlength{\oddsidemargin}{#1}
	\setlength{\evensidemargin}{#1}
	\setlength{\topmargin}{#1 / 2}
	\ifthenelse{\boolean{#2}}{\setlength{\headheight}{15pt}% header material
		\setlength{\headsep}{20pt}}{\setlength{\headheight}{0pt}%
		\setlength{\headsep}{0pt}}
	\ifthenelse{\boolean{#3}}{\setlength{\footskip}{35pt}}% footer material
		{\setlength{\footskip}{0pt}}
	\setlength{\textheight}{\paperheight - \footskip - \headsep - \headheight - \topmargin - #1}
	\setlength{\textwidth}{\paperwidth - (#1 * 2) } %  - (#1 / 3)}
    \addtolength\oddsidemargin{-0.5cm}
    \addtolength\evensidemargin{-1cm}
    \textwidth=\dimexpr\textwidth-1cm\relax
	\setlength\parskip{\bigskipamount}
	\setlength\parindent{0pt}
	\onehalfspacing
}

\SetMargins{2.2cm}{true}{true} %2.5cm margin, enable head and foot skips
%\linespread{1.5} %% 1.5 spacing for document body (dealt with above) 

%rename Bibliography to references when using bibtex
\renewcommand\bibname{References}
% set some full details
\newcommand\ackname{Acknowledgements}

\newcommand{\keywords}[1]{\vspace{1cm}\newline\textbf{Keywords:} \textit{#1}}
 
\newcommand{\plagdeclaration}{
    \chapter*{Declaration}
    I declare that the work presented for assessment in this submission is my own, that it has not previously been presented for another assessment, and that work completed by others has been appropriately acknowledged.
    \vspace{1.5cm} \newline
    \textbf{Name}: \myname{} \hspace{2cm} \textbf{Date}: \today 
    \thispagestyle{empty} 
}
\newcommand{\plagdeclarationblank}{
    \chapter*{Declaration}
    I declare that the work presented for assessment in this submission is my own, that it has not previously been presented for another assessment, and that work completed by others has been appropriately acknowledged.
    \vspace{3cm} \newline
    \textbf{Name}: \noindent\rule{5.5cm}{0.4pt}  \hspace{1.5cm} \textbf{Date}: \noindent\rule{4cm}{0.4pt} 
    \thispagestyle{empty} 
} 

\renewcommand{\headrulewidth}{\iffloatpage{0pt}{0.4pt}}

\pagestyle{fancy}
\lhead{\sectionmark}
\rhead{}
\cfoot{\thepage}
\renewcommand{\chaptermark}[1]{\markboth{\MakeUppercase{\chaptername}\ \thechapter}{}}


%\fancypagestyle{plain}{\fancyhf{}\fancyhead[R]{\thepage}}
\fancyhf{}\fancyhead[R]{\thepage}
\fancyhead[L]{\iffloatpage{}{\slshape \rightmark}}

\newcommand{\mylocation}{Kristiansand, Norway}

\renewcommand{\maketitle}{%
	\begin{titlepage}%
	\begin{center}%
	\ifthenelse{\boolean{\Logo}}{\includegraphics[scale=0.15]{\NUCLogo}\vfill}{\vspace*{\fill}}%
	\ifthenelse{\boolean{\TitleBox}}{
	\Ovalbox{\begin{minipage}[c][\height + 6cm][c]{(\textwidth * 3) / 4}\begin{center}%
	\vspace*{\fill}\LARGE\textsc{\@title}%
	\large\vfill%
	Submitted in \DegType\\%
	of the requirements of the degree of\vskip 0.5em\textsc{\Degree}\vskip 0.5em%
	of Noroff University College%
	\vfill\Large\@author\vspace*{\fill}%
	\end{center}\end{minipage}}}{%

	\begin{center}%
	\vspace*{\fill}\LARGE\textsc{\@title}%
	\large\vfill%
	Submitted in \DegType\\%
	of the requirements of the degree of\vskip 0.5em\textsc{\Degree}\vskip 0.5em%
	of Noroff University College%
	\vfill\Large\@author\vspace*{\fill}%
	\end{center}}%

	\vfill\normalsize%
	\emph{\mylocation}\\%
	\ifcase\month\or  January\or February\or March\or April\or May\or June\or July\or August\or September\or October\or November\or December\fi
  \space\number\year
	\month \year  %@date
  \end{center}%
	\end{titlepage}%
}


\if@titlepage
  \newenvironment{ack}{%
      \titlepage
      \null\vfil
      \@beginparpenalty\@lowpenalty
      \begin{center}%
        \bfseries \ackname
        \@endparpenalty\@M
      \end{center}}%
     {\par\vfil\null\endtitlepage}
\else
  \newenvironment{ack}{%
      \if@twocolumn
        \section*{\ackname}%
      \else
        \small
        \begin{center}%
          {\bfseries \ackname\vspace{-.5em}\vspace{\z@}}%
        \end{center}%
        \quotation
      \fi}
      {\if@twocolumn\else\endquotation\fi}
\fi

\newcommand\acmname{ACM Computing Classification System Classification}

\if@titlepage
  \newenvironment{acm}{%
      \titlepage
      \null\vfil
      \@beginparpenalty\@lowpenalty
      \begin{center}%
        \bfseries \acmname
        \@endparpenalty\@M
      \end{center}}%
     {\par\vfil\null\endtitlepage}
\else
  \newenvironment{acm}{%
      \if@twocolumn
        \section*{\acmname}%
      \else
        \small
        \begin{center}%
          {\bfseries \ackname\vspace{-.5em}\vspace{\z@}}%
        \end{center}%
        \quotation
      \fi}
      {\if@twocolumn\else\endquotation\fi}
\fi
%% Providing Section guidence
\newcommand{\guidebox}[1]{%
    \colorbox{gray!20}{%
    \begin{minipage}{0.9\textwidth}
    \small{\textbf{\textsc{NUC Bachelor Project Guidance}}:\newline}
    \noindent\rule{\textwidth}{0.4pt}
    \small{\textit{#1}}
    \end{minipage}}
    \newline
}


\newcommand{\guideabs}{\guidebox{Your Abstract should succinctly sum up your work in 200-300 words, You should include a brief rational for the research, the approach taken and the results/findings and /or details of the artefact produced. Choose 3-5 keywords to include in the \textbf{Keywords} section below. This must \textbf{not} exceed one page.}\newline}


\newcommand{\guideack}{\guidebox{Your Acknowledgements are generally free form in structure. You should include anyone who has assisted you with the project. Any funders of the research (or your studies) are typically mentioned here as well. This must \textbf{not} exceed one page.}}

\newcommand{\guideintro}{\guidebox{The Introduction sets the scene, contextualises your research, and provides an overview of the project. This chapter contains some commonly used sections. At a minimum you should define and populate the following:
    \begin{enumerate}
        \item Problem Statement
        \item Research objectives
        \item Scope and Limits
%\section{Document Conventions} %enable if you have specific formatting styles you want to tell the reader about
        \item Document Structure
    \end{enumerate}
    This chapter justifies your research and limits the scope of your investigation.}}
\newcommand{\guidelit}{\guidebox{The Literature Review has two primary goals it needs to address.
        \begin{enumerate}
        \item \textbf{A review of related literature and research}
        Looking at what other researchers have investigated in the field. This is important for basing your work on and for having something to compare your results to in later chapters.
        \item \textbf{Technology review and primer}
        An exploration of appropriate technologies that you will be using in your investigation. it also is where you need to explain any particularly technical concepts that readers may not be familiar with.
    \end{enumerate}
The majority of your references should appear in your literature review chapter. Any major work(s) you rely on later should be introduced here.    
}}
\newcommand{\guideanalysis}{\guidebox{\textbf{Analysis} based projects need to detail the process of data collection, processing, and analysis. Where did you collect data? How did you collect it? How did you store and process your data?  An analysis is about how results were produced.  The interpretation of these results is dealt with in the following chapter.}}
\newcommand{\guideimplementation}{\guidebox{\textbf{Implementation} driven projects usually aim at the production of an `artefact' - be this code, a dataset, or a physical object such as a game. This chapter needs to discuss both the design process followed (why did you make it like this?) and the resulting implementation approach (how did you build it?). Any design/implementation trade-offs made should be discussed.}}
\newcommand{\guideresults}{\guidebox{The Results chapter is where the results of your investigation are presented. These can take many different forms based on how the project was conducted. The key here is to critically evaluate your results and to compare and contrast with results from the larger body of literature in the field (as you introduced in the Literature Review Chapter earlier).}}
\newcommand{\guideconclusion}{\guidebox{The Conclusion sums up the work and draws the presentation of your research presentation and argument to a close.  There should be no new information or facts relating to the research introduced in this section. Typically this chapter is structured as follows:
    \begin{enumerate}
        \item {Introduction}
        Draws together the preceding chapters
        \item {Summary of Research}
        Briefly summaries the work conducted 2-3 sentences per chapter is sufficient
        \item {Research Objectives}
        For each of your research objectives you laid out in the Introduction you should evaluate the degree to which it has been met (and provide a link back to the section(s) which justify this).
        \item {Research Contribution}
        Sum up what contribution your research has made, clearly define any outputs or artefacts produced.
        \item {Future Work}
        You built your work on the `shoulders of giants'. How could someone continue to build on your work? Choose 3-4 areas of further exploration and/or expansion of your work.
    \end{enumerate}
}}

%% code for handling word counts
\newcommand{\detailtexcount}[1]{%
  \immediate\write18{texcount -merge -sum -q #1.tex output.bbl > #1.wcdetail }%
  \verbatiminput{#1.wcdetail}%
}

\newcommand{\quickwordcount}[1]{%
  \immediate\write18{texcount -1 -sum -merge -q #1.tex output.bbl > #1-words.sum }%
  \input{#1-words.sum} words%
}

\newcommand{\quickwordcountnoref}[1]{%
  \immediate\write18{texcount -1 -sum -merge -q #1.tex  > #1-words.sum }%
  \input{#1-words.sum} words%
}

\newcommand{\noroffcount}[1]{%
  \immediate\write18{texcount -v0 -q -total  -sum -merge -q #1.tex > #1-words.noroff }%
  \input{#1-words.noroff} %
}
%
%Words with Refs:\quickwordcount{main}
%
%Words Without refs: \quickwordcountnoref{main}

\newcommand{\NUCwordcount}[1]{
    \chapter*{Word count metrics}
    \framebox{%
    \begin{minipage}{0.95\textwidth}
    \textbf{NUC Bachelor Project Word Count}:\\
    \noroffcount{#1}
    NOTE: References are excluded.
    \end{minipage}}
}

\newcommand{\OrjansHref}[3][black]{\href{#2}{\color{#1}{#3}}}%

%%% ---------------------------- END OF CLASS ----------------------------