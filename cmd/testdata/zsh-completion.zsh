if [[ $1 == --child ]]; then
    PS1='probe> '
    fpath=("${PKGS_GIT_COMPLETION:h}" "${PKGS_COMPLETION:h}" $fpath)
    autoload -Uz compinit
    compinit -u -D
    # The Git-distributed script can be installed as git-completion.zsh or _git.
    _git() { source "$PKGS_GIT_COMPLETION"; }
    compdef _git git
    if [[ $PKGS_LOAD_MODE == source ]]; then
        source "$PKGS_COMPLETION"
        source "$PKGS_COMPLETION"
    fi
    bindkey -e
    probe-completion() {
        zle expand-or-complete
        print -r -- "$BUFFER" >> "$PKGS_RESULT"
        print -r -- '__COMPLETED__'
    }
    zle -N probe-completion
    bindkey '^I' probe-completion
    print -r -- '__INITIALIZED__'
else
    zmodload zsh/zpty
    zmodload zsh/zselect
    zpty -b shell "$PKGS_ZSH" -df
    trap 'zpty -d shell' EXIT
    wait-for-output() {
        local chunk received=''
        local -i attempt
        for (( attempt=0; attempt < 1000; attempt++ )); do
            if zpty -r shell chunk; then
                received+=$chunk
                [[ $received == *$1* ]] && return 0
            fi
            zselect -t 1
        done
        print -ru2 -- "Timed out waiting for $1: $received"
        return 1
    }
    zpty -w shell "source ${(q)0} --child"
    wait-for-output __INITIALIZED__ || exit 1
    while IFS= read -r input; do
        zpty -w -n shell "$input"$'\t'
        wait-for-output __COMPLETED__ || exit 1
        zpty -w -n shell $'\C-c'
    done < "$PKGS_INPUT"
fi
