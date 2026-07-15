# bash completion for ghostshell
# Install: ghostshell completion bash | sudo tee /usr/share/bash-completion/completions/ghostshell
# (packages install this automatically)
#
# Dynamic candidates from `ghostshell __complete` are intentionally left unquoted
# inside compgen -W so each newline-separated name becomes a separate word.
# `ghostshell __complete` sanitizes those names (rejecting whitespace and shell/IFS
# metacharacters) so an attacker-controlled filename cannot inject word breaks
# or shell syntax here.

_ghostshell() {
    local cur prev sub
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    sub="${COMP_WORDS[1]}"

    # Top-level subcommand.
    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=( $(compgen -W "rec play ls tail tree analyze search export prune ansible init completion version --check help" -- "$cur") )
        return
    fi

    # Flags that take a value.
    case "$prev" in
        --speed|--idle|-n)
            return ;;  # numeric, no completion
        -o)
            COMPREPLY=( $(compgen -f -- "$cur") )
            return ;;
        --user)
            COMPREPLY=( $(compgen -W "$(ghostshell __complete users 2>/dev/null)" -- "$cur") )
            return ;;
    esac

    case "$sub" in
        init)
            COMPREPLY=( $(compgen -W "--reset-password --clear-password --enable-ssh-forcecommand --disable-ssh-forcecommand" -- "$cur") ) ;;
        rec)
            COMPREPLY=( $(compgen -W "-q -o" -- "$cur") ) ;;
        play)
            # auto-detect: complete both local sessions and central sessions
            COMPREPLY=( $(compgen -W "--speed --idle $(ghostshell __complete local-sessions 2>/dev/null) $(ghostshell __complete central-sessions 2>/dev/null)" -- "$cur") ) ;;
        ls)
            COMPREPLY=( $(compgen -W "--all --user" -- "$cur") ) ;;
        tail)
            COMPREPLY=( $(compgen -W "-f -n $(ghostshell __complete central-sessions 2>/dev/null)" -- "$cur") ) ;;
        tree)
            # `tree <session-id>` shows a session's process tree; --json emits it as JSON.
            COMPREPLY=( $(compgen -W "--json $(ghostshell __complete central-sessions 2>/dev/null)" -- "$cur") ) ;;
        analyze)
            # `analyze <session-id>` runs the deterministic + optional local-AI pass.
            COMPREPLY=( $(compgen -W "--no-ai --model --allow-remote $(ghostshell __complete central-sessions 2>/dev/null)" -- "$cur") ) ;;
        export)
            COMPREPLY=( $(compgen -W "$(ghostshell __complete central-sessions 2>/dev/null)" -- "$cur") ) ;;
        search)
            COMPREPLY=( $(compgen -W "--from --to --user -i --all" -- "$cur") ) ;;
        ansible)
            COMPREPLY=( $(compgen -W "list show" -- "$cur") ) ;;
        completion)
            COMPREPLY=( $(compgen -W "bash" -- "$cur") ) ;;
        *)
            COMPREPLY=() ;;
    esac
}
complete -F _ghostshell ghostshell
