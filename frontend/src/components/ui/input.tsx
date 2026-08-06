import type { InputHTMLAttributes } from 'react'
import { cn } from '@/lib/utils'

export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        'h-10 w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] px-3 text-sm text-[var(--color-text)]',
        'placeholder:text-[var(--color-text-faint)] outline-none transition-colors',
        'focus:border-[var(--color-accent)]',
        className,
      )}
      {...props}
    />
  )
}
