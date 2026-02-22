type RuntimePlaceholderProps = {
  title: string;
};

export function RuntimePlaceholder({ title }: RuntimePlaceholderProps) {
  return (
    <div className="grid gap-2">
      <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
      <p className="text-sm text-muted-foreground">
        This runtime page is prepared in the sidebar and will be implemented next.
      </p>
    </div>
  );
}
