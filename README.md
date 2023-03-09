# picold

1. parse ELF header and locate sections
2. parse the section that holds the section names
3. parse the section that holds the symbol names
4. parse any relocation entries
5. solve relocation entry values
6. stitch ELF file back together
 - resolve all symbols into symtab
   - optional
 - create program headers for sections
   - only for sections that are
     - executable
     - loadable
 - concat all the sections