(function() {var implementors = {};
implementors["cumulus_client_consensus_relay_chain"] = [{"text":"impl&lt;Client, Block, CIDP&gt; Verifier&lt;Block&gt; for <a class=\"struct\" href=\"cumulus_client_consensus_relay_chain/struct.Verifier.html\" title=\"struct cumulus_client_consensus_relay_chain::Verifier\">Verifier</a>&lt;Client, Block, CIDP&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Block: BlockT,<br>&nbsp;&nbsp;&nbsp;&nbsp;Client: ProvideRuntimeApi&lt;Block&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;Client as ProvideRuntimeApi&lt;Block&gt;&gt;::Api: BlockBuilderApi&lt;Block&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;CIDP: CreateInherentDataProviders&lt;Block, <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.unit.html\">()</a>&gt;,&nbsp;</span>","synthetic":false,"types":["cumulus_client_consensus_relay_chain::import_queue::Verifier"]}];
implementors["sc_consensus_subspace"] = [{"text":"impl&lt;Block, Client, SelectChain, CAW, CIDP&gt; Verifier&lt;Block&gt; for <a class=\"struct\" href=\"sc_consensus_subspace/struct.SubspaceVerifier.html\" title=\"struct sc_consensus_subspace::SubspaceVerifier\">SubspaceVerifier</a>&lt;Block, Client, SelectChain, CAW, CIDP&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Block: BlockT,<br>&nbsp;&nbsp;&nbsp;&nbsp;Client: HeaderMetadata&lt;Block, Error = Error&gt; + HeaderBackend&lt;Block&gt; + ProvideRuntimeApi&lt;Block&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a> + AuxStore,<br>&nbsp;&nbsp;&nbsp;&nbsp;Client::Api: BlockBuilderApi&lt;Block&gt; + <a class=\"trait\" href=\"sp_consensus_subspace/trait.SubspaceApi.html\" title=\"trait sp_consensus_subspace::SubspaceApi\">SubspaceApi</a>&lt;Block&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;SelectChain: SelectChain&lt;Block&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;CAW: CanAuthorWith&lt;Block&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;CIDP: CreateInherentDataProviders&lt;Block, <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.unit.html\">()</a>&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;CIDP::InherentDataProviders: InherentDataProviderExt + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a>,&nbsp;</span>","synthetic":false,"types":["sc_consensus_subspace::SubspaceVerifier"]}];
implementors["sc_network_test"] = [{"text":"impl&lt;B:&nbsp;BlockT&gt; Verifier&lt;B&gt; for <a class=\"struct\" href=\"sc_network_test/struct.PassThroughVerifier.html\" title=\"struct sc_network_test::PassThroughVerifier\">PassThroughVerifier</a>","synthetic":false,"types":["sc_network_test::PassThroughVerifier"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()