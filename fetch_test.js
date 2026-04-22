fetch('https://testnep1453.github.io/nep1/').then(r=>r.text()).then(t=>{ 
    const match = t.match(/assets\/index-[^\"]*\.js/); 
    if (match) { 
        console.log('JS FILE =', match[0]); 
        fetch('https://testnep1453.github.io/nep1/'+match[0]).then(r2=>r2.text()).then(js=>{ 
            console.log('Contains Supabase URL:', js.includes('ncihoahtxsdsiethcwwa')); 
            console.log('Contains Anon Key:', js.includes('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9')); 
        }); 
    }
})
